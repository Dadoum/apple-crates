use crate::backend::icon::{
    normalize_png_for_display, write_icon_variants, IPAD_ICON_NAMES, IPAD_PRIMARY_ICON_NAME,
    IPHONE_ICON_NAMES, IPHONE_PRIMARY_ICON_NAME,
};
use crate::backend::paths::app_data_dir;
use crate::backend::{runtime as backend_runtime, BackendError, BackendResult};
use crate::domain::{
    AppEntitlement, AppMetadata, EntitlementValue, EntitlementsSource, IpaApp, NestedBundle,
    NestedBundleKind, Patch, SupportedDeviceFamily,
};
use apple_codesign::{
    sign_bundle, BundleSigningSettings, ProvisioningProfile, RustCryptoCmsSigner,
};
use async_zip::base::read::mem::ZipFileReader as MemoryZipFileReader;
use async_zip::base::write::ZipFileWriter;
use async_zip::tokio::read::fs::ZipFileReader;
use async_zip::{Compression, ZipEntry, ZipEntryBuilder};
use flate2::write::DeflateEncoder;
use flate2::Compression as FlateCompression;
use futures_lite::io::AsyncReadExt;
use plist::{Dictionary, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Write as _};
use std::path::{Component, Path, PathBuf};
use tempfile::{Builder as TempBuilder, TempDir};
use tokio::io::AsyncWriteExt;
use tokio::task::JoinSet;
use walkdir::WalkDir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const MAX_EXTRACTION_WORKERS: usize = 4;
const MAX_PACKAGING_WORKERS: usize = 4;
const FAST_DEFLATE_LEVEL: u32 = 4;
const IN_MEMORY_EXTRACTION_LIMIT: u64 = 256 * 1024 * 1024;

pub(crate) struct IpaSigningRequest {
    pub(crate) source_path: PathBuf,
    pub(crate) destination: SigningDestination,
    pub(crate) metadata: AppMetadata,
    pub(crate) bundle_id_replacements: BTreeMap<String, String>,
    pub(crate) icon_override_path: Option<PathBuf>,
    pub(crate) strip_extensions: bool,
    pub(crate) team_id: String,
    pub(crate) provisioning_profiles: BTreeMap<String, Vec<u8>>,
    pub(crate) private_key_pem: Vec<u8>,
    pub(crate) certificate_der: Vec<u8>,
}

pub(crate) enum SigningDestination {
    Ipa(PathBuf),
    AppBundle,
}

pub(crate) enum SigningArtifact {
    Ipa(PathBuf),
    AppBundle(SignedAppBundle),
}

pub(crate) struct SignedAppBundle {
    app_path: PathBuf,
    _work_dir: TempDir,
}

impl SignedAppBundle {
    pub(crate) fn path(&self) -> &Path {
        &self.app_path
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IpaSigningProgress {
    Extracting { completed: usize, total: usize },
    Patching,
    Signing,
    Packaging { completed: usize, total: usize },
    Saving,
    Ready,
}

pub(crate) async fn read_ipa(path: PathBuf, patches: Vec<Patch>) -> BackendResult<IpaApp> {
    backend_runtime::run_send("IPA reader", read_ipa_async(path, patches)).await?
}

pub(crate) async fn sign_ipa(
    request: IpaSigningRequest,
    progress: impl FnMut(IpaSigningProgress) + Send + 'static,
) -> BackendResult<SigningArtifact> {
    backend_runtime::run_send("IPA signer", sign_ipa_async(request, progress)).await?
}

async fn read_ipa_async(path: PathBuf, patches: Vec<Patch>) -> BackendResult<IpaApp> {
    let reader = ZipFileReader::new(&path)
        .await
        .map_err(|error| BackendError::Zip(format!("{}: {error}", path.display())))?;

    let info_index = reader
        .file()
        .entries()
        .iter()
        .position(|entry| entry_name(entry).is_some_and(is_app_info_plist))
        .ok_or_else(|| {
            BackendError::Zip("IPA does not contain Payload/*.app/Info.plist.".to_string())
        })?;
    let info_path = entry_name(&reader.file().entries()[info_index])
        .ok_or_else(|| BackendError::Zip("IPA Info.plist entry name is invalid.".to_string()))?;
    let app_prefix = info_path
        .strip_suffix("Info.plist")
        .ok_or_else(|| BackendError::Zip("IPA Info.plist entry path is invalid.".to_string()))?
        .to_string();

    let info_bytes = read_entry(&reader, info_index, "Info.plist").await?;
    let info = plist::from_bytes::<Dictionary>(&info_bytes)
        .map_err(|error| BackendError::Plist(format!("IPA Info.plist: {error}")))?;

    let bundle_id = required_plist_string(&info, "CFBundleIdentifier")?;
    let executable = required_plist_string(&info, "CFBundleExecutable")?;
    let version = required_plist_string(&info, "CFBundleShortVersionString")?;
    let build = required_plist_string(&info, "CFBundleVersion")?;
    let minimum_os = required_plist_string(&info, "MinimumOSVersion")?;
    let name = plist_string(&info, "CFBundleDisplayName")
        .or_else(|| plist_string(&info, "CFBundleName"))
        .unwrap_or(executable);
    let supported_devices = supported_devices(&info);
    let nested_bundles = read_nested_signable_bundles(&reader, &app_prefix).await?;

    let icon_path = extract_icon(&reader, &app_prefix, &info, bundle_id).await;
    let (entitlements_source, entitlements) = match extract_entitlements(&reader, &app_prefix).await
    {
        Some(entitlements) => (EntitlementsSource::Embedded, entitlements),
        None => (EntitlementsSource::GeneratedFallback, Vec::new()),
    };

    Ok(IpaApp {
        metadata: AppMetadata {
            name: name.to_string(),
            bundle_id: bundle_id.to_string(),
            version: version.to_string(),
            build: build.to_string(),
            executable: executable.to_string(),
            minimum_os: minimum_os.to_string(),
            supported_devices,
        },
        nested_bundles,
        path: path.to_string_lossy().to_string(),
        icon_path: icon_path.map(|path| path.to_string_lossy().to_string()),
        entitlements,
        entitlements_source,
        patches,
    })
}

async fn read_nested_signable_bundles(
    reader: &ZipFileReader,
    app_prefix: &str,
) -> BackendResult<Vec<NestedBundle>> {
    let candidates = reader
        .file()
        .entries()
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            let path = entry_name(entry)?;
            nested_signable_bundle_kind(path, app_prefix)
                .map(|kind| (index, path.to_string(), kind))
        })
        .collect::<Vec<_>>();
    let mut bundles = Vec::with_capacity(candidates.len());

    for (index, path, kind) in candidates {
        let bytes = read_entry(reader, index, &path).await?;
        let info = plist::from_bytes::<Dictionary>(&bytes)
            .map_err(|error| BackendError::Plist(format!("{path}: {error}")))?;
        if plist_string(&info, "CFBundleExecutable").is_none() {
            continue;
        }
        let bundle_id = required_plist_string(&info, "CFBundleIdentifier")?.to_string();
        let name = plist_string(&info, "CFBundleDisplayName")
            .or_else(|| plist_string(&info, "CFBundleName"))
            .unwrap_or(&bundle_id)
            .to_string();
        bundles.push(NestedBundle {
            name,
            bundle_id,
            kind,
        });
    }

    bundles.sort_by(|left, right| left.bundle_id.cmp(&right.bundle_id));
    bundles.dedup_by(|left, right| left.bundle_id == right.bundle_id);
    Ok(bundles)
}

fn nested_signable_bundle_kind(path: &str, app_prefix: &str) -> Option<NestedBundleKind> {
    let relative = path
        .strip_prefix(app_prefix)
        .and_then(|path| path.strip_suffix("/Info.plist"))?;
    if relative.is_empty() {
        return None;
    }
    let extension = Path::new(relative)
        .extension()
        .and_then(|extension| extension.to_str())?;
    if extension.eq_ignore_ascii_case("appex") {
        Some(NestedBundleKind::AppExtension)
    } else if extension.eq_ignore_ascii_case("app") {
        Some(NestedBundleKind::App)
    } else {
        None
    }
}

fn is_app_info_plist(path: &str) -> bool {
    path.strip_prefix("Payload/")
        .and_then(|path| path.strip_suffix("/Info.plist"))
        .is_some_and(|bundle| bundle.ends_with(".app") && !bundle.contains('/'))
}

fn entry_name(entry: &async_zip::ZipEntry) -> Option<&str> {
    entry.filename().as_str().ok()
}

fn required_plist_string<'a>(info: &'a Dictionary, key: &str) -> BackendResult<&'a str> {
    plist_string(info, key)
        .ok_or_else(|| BackendError::Plist(format!("IPA Info.plist is missing string key {key}.")))
}

async fn read_entry(reader: &ZipFileReader, index: usize, label: &str) -> BackendResult<Vec<u8>> {
    let mut entry_reader = reader
        .reader_without_entry(index)
        .await
        .map_err(|error| BackendError::Zip(format!("Failed to read {label} from IPA: {error}")))?;
    let mut data = Vec::new();
    entry_reader.read_to_end(&mut data).await.map_err(|error| {
        BackendError::Zip(format!("Failed to extract {label} from IPA: {error}"))
    })?;
    Ok(data)
}

fn plist_string<'a>(plist: &'a Dictionary, key: &str) -> Option<&'a str> {
    plist.get(key).and_then(Value::as_string)
}

fn supported_devices(info: &Dictionary) -> Vec<SupportedDeviceFamily> {
    let Some(Value::Array(families)) = info.get("UIDeviceFamily") else {
        return Vec::new();
    };

    let mut devices = families
        .iter()
        .filter_map(|value| value.as_unsigned_integer())
        .filter_map(SupportedDeviceFamily::from_device_family_id)
        .collect::<Vec<_>>();
    devices.sort();
    devices.dedup();
    devices
}

async fn extract_icon(
    reader: &ZipFileReader,
    app_prefix: &str,
    info: &Dictionary,
    bundle_id: &str,
) -> Option<PathBuf> {
    let mut candidates = icon_candidates(info);
    candidates.reverse();

    for candidate in candidates {
        if let Some((index, name)) = find_icon_entry(reader, app_prefix, &candidate) {
            if let Ok(bytes) = read_entry(reader, index, name).await {
                if let Some(path) = cache_icon(bundle_id, &bytes) {
                    return Some(path);
                }
            }
        }
    }

    let fallback = reader
        .file()
        .entries()
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            let name = entry_name(entry)?;
            let lower = name.to_ascii_lowercase();
            (name.starts_with(app_prefix)
                && lower.ends_with(".png")
                && (lower.contains("appicon") || lower.contains("icon")))
            .then_some((index, name, entry.compressed_size()))
        })
        .max_by_key(|(_, _, size)| *size)
        .map(|(index, name, _)| (index, name));

    let (index, name) = fallback?;
    let bytes = read_entry(reader, index, name).await.ok()?;
    cache_icon(bundle_id, &bytes)
}

fn icon_candidates(info: &Dictionary) -> Vec<String> {
    let mut candidates = Vec::new();
    append_icon_candidates(info.get("CFBundleIconFiles"), &mut candidates);
    append_icon_candidates_from_icons(info.get("CFBundleIcons"), &mut candidates);
    append_icon_candidates_from_icons(info.get("CFBundleIcons~ipad"), &mut candidates);
    candidates
}

fn append_icon_candidates(value: Option<&Value>, candidates: &mut Vec<String>) {
    match value {
        Some(Value::Array(values)) => {
            candidates.extend(
                values
                    .iter()
                    .filter_map(Value::as_string)
                    .map(str::to_string),
            );
        }
        Some(Value::String(value)) => candidates.push(value.clone()),
        _ => {}
    }
}

fn append_icon_candidates_from_icons(value: Option<&Value>, candidates: &mut Vec<String>) {
    let Some(Value::Dictionary(icons)) = value else {
        return;
    };
    let Some(Value::Dictionary(primary_icon)) = icons.get("CFBundlePrimaryIcon") else {
        return;
    };
    append_icon_candidates(primary_icon.get("CFBundleIconFiles"), candidates);
}

fn find_icon_entry<'a>(
    reader: &'a ZipFileReader,
    app_prefix: &str,
    candidate: &str,
) -> Option<(usize, &'a str)> {
    let candidate = candidate.trim_start_matches('/');
    let forms = if candidate.ends_with(".png") {
        vec![candidate.to_string()]
    } else {
        vec![
            format!("{candidate}@3x.png"),
            format!("{candidate}@2x.png"),
            format!("{candidate}.png"),
            candidate.to_string(),
        ]
    };

    reader
        .file()
        .entries()
        .iter()
        .enumerate()
        .find_map(|(index, entry)| {
            let name = entry_name(entry)?;
            let relative = name.strip_prefix(app_prefix)?;
            forms
                .iter()
                .any(|form| relative == form || relative.ends_with(&format!("/{form}")))
                .then_some((index, name))
        })
}

fn cache_icon(bundle_id: &str, bytes: &[u8]) -> Option<PathBuf> {
    let normalized = match normalize_png_for_display(bytes) {
        Ok(normalized) => normalized,
        Err(error) => {
            log::warn!("Failed to normalize app icon for {bundle_id}: {error}");
            return None;
        }
    };
    let mut path = app_data_dir()?.join("icons");
    fs::create_dir_all(&path).ok()?;
    path.push(format!("{}.png", cache_safe_name(bundle_id)));
    fs::write(&path, normalized).ok()?;
    Some(path)
}

fn cache_safe_name(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

async fn extract_entitlements(
    reader: &ZipFileReader,
    app_prefix: &str,
) -> Option<Vec<AppEntitlement>> {
    let entry_index = reader.file().entries().iter().position(|entry| {
        entry_name(entry) == Some(&format!("{app_prefix}embedded.mobileprovision"))
    })?;
    let bytes = read_entry(reader, entry_index, "embedded.mobileprovision")
        .await
        .ok()?;
    let plist = embedded_plist(&bytes)?;
    let entitlements = plist.get("Entitlements")?.as_dictionary()?;
    Some(entitlements_from_dictionary(entitlements))
}

fn embedded_plist(bytes: &[u8]) -> Option<Dictionary> {
    let start = find_bytes(bytes, b"<?xml")?;
    let end = find_bytes(&bytes[start..], b"</plist>")? + start + b"</plist>".len();
    plist::from_reader(Cursor::new(&bytes[start..end])).ok()
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn entitlements_from_dictionary(entitlements: &Dictionary) -> Vec<AppEntitlement> {
    entitlements
        .iter()
        .map(|(key, value)| AppEntitlement {
            key: key.clone(),
            value: entitlement_value(value),
        })
        .collect()
}

fn entitlement_value(value: &Value) -> EntitlementValue {
    match value {
        Value::String(value) => EntitlementValue::String(value.clone()),
        Value::Boolean(value) => EntitlementValue::Boolean(*value),
        Value::Integer(value) => value
            .as_signed()
            .map(EntitlementValue::Integer)
            .unwrap_or_else(|| EntitlementValue::String(value.to_string())),
        Value::Real(value) => EntitlementValue::Number(*value),
        Value::Array(values) => {
            EntitlementValue::Array(values.iter().map(entitlement_value).collect())
        }
        Value::Dictionary(values) => EntitlementValue::Dictionary(
            values
                .iter()
                .map(|(key, value)| (key.clone(), entitlement_value(value)))
                .collect(),
        ),
        Value::Data(value) => EntitlementValue::Data(value.clone()),
        Value::Date(value) => EntitlementValue::Date(value.to_xml_format()),
        Value::Uid(value) => EntitlementValue::Uid(value.get()),
        _ => EntitlementValue::Unknown("Value".into()),
    }
}

async fn sign_ipa_async(
    request: IpaSigningRequest,
    mut progress: impl FnMut(IpaSigningProgress) + Send,
) -> BackendResult<SigningArtifact> {
    let work_dir = TempBuilder::new()
        .prefix("super-sideloader-sign-")
        .tempdir()
        .map_err(|source| BackendError::Io {
            action: "Create temporary IPA signing folder",
            path: std::env::temp_dir(),
            source,
        })?;

    extract_ipa(&request.source_path, work_dir.path(), &mut progress).await?;
    let app_path = root_app_bundle(work_dir.path())?;
    progress(IpaSigningProgress::Patching);
    if request.strip_extensions {
        strip_app_extensions(&app_path)?;
    }
    patch_app_bundle(
        &app_path,
        &request.metadata,
        request.icon_override_path.as_deref(),
    )?;
    patch_nested_bundle_identifiers(&app_path, &request.bundle_id_replacements)?;
    progress(IpaSigningProgress::Signing);
    sign_staged_app(&app_path, &request)?;

    if matches!(&request.destination, SigningDestination::AppBundle) {
        progress(IpaSigningProgress::Ready);
        return Ok(SigningArtifact::AppBundle(SignedAppBundle {
            app_path,
            _work_dir: work_dir,
        }));
    }

    let SigningDestination::Ipa(output_path) = request.destination else {
        unreachable!("app bundle destination returned above");
    };

    let output_parent = output_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(output_parent).map_err(|source| BackendError::Io {
        action: "Create signed IPA output folder",
        path: output_parent.to_path_buf(),
        source,
    })?;
    let output_temp = TempBuilder::new()
        .prefix(".super-sideloader-")
        .suffix(".ipa.tmp")
        .tempfile_in(output_parent)
        .map_err(|source| BackendError::Io {
            action: "Create temporary signed IPA",
            path: output_parent.to_path_buf(),
            source,
        })?
        .into_temp_path();

    package_ipa(work_dir.path(), output_temp.as_ref(), &mut progress).await?;
    progress(IpaSigningProgress::Saving);
    output_temp
        .persist(&output_path)
        .map_err(|error| BackendError::Io {
            action: "Save signed IPA",
            path: output_path.clone(),
            source: error.error,
        })?;
    Ok(SigningArtifact::Ipa(output_path))
}

fn strip_app_extensions(app_path: &Path) -> BackendResult<()> {
    let mut entries = WalkDir::new(app_path).follow_links(false).into_iter();
    let mut extension_paths = Vec::new();

    while let Some(entry) = entries.next() {
        let entry = entry.map_err(|error| {
            BackendError::Message(format!(
                "Failed to inspect app extensions under {}: {error}",
                app_path.display()
            ))
        })?;
        if entry.file_type().is_dir()
            && entry
                .path()
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("appex"))
        {
            extension_paths.push(entry.into_path());
            entries.skip_current_dir();
        }
    }

    for path in extension_paths {
        fs::remove_dir_all(&path).map_err(|source| BackendError::Io {
            action: "Remove app extension",
            path,
            source,
        })?;
    }
    Ok(())
}

async fn extract_ipa(
    source_path: &Path,
    destination: &Path,
    progress: &mut impl FnMut(IpaSigningProgress),
) -> BackendResult<()> {
    let reader = ExtractionReader::open(source_path).await?;
    let total = reader.file().entries().len();
    progress(IpaSigningProgress::Extracting {
        completed: 0,
        total,
    });

    let mut files = Vec::new();
    let mut completed = 0;
    for index in 0..total {
        let entry = &reader.file().entries()[index];
        let name = entry_name(entry)
            .ok_or_else(|| BackendError::Zip("IPA contains an invalid entry name.".to_string()))?
            .to_string();
        let relative_path = safe_zip_entry_path(&name)?;
        let output_path = destination.join(&relative_path);
        let unix_permissions = entry.unix_permissions();
        if unix_permissions.is_some_and(is_symlink_mode) {
            return Err(BackendError::Zip(format!(
                "IPA contains unsupported symbolic link entry {name}."
            )));
        }

        if name.ends_with('/') {
            fs::create_dir_all(&output_path).map_err(|source| BackendError::Io {
                action: "Create extracted IPA folder",
                path: output_path,
                source,
            })?;
            completed += 1;
            report_extracting_progress(progress, completed, total);
            continue;
        }

        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent).map_err(|source| BackendError::Io {
                action: "Create extracted IPA folder",
                path: parent.to_path_buf(),
                source,
            })?;
        }
        files.push(ExtractionPlan {
            index,
            name,
            output_path,
            unix_permissions,
        });
    }

    let mut files = files.into_iter();
    let mut workers = JoinSet::new();
    let concurrency = archive_worker_count(MAX_EXTRACTION_WORKERS);
    for _ in 0..concurrency {
        let Some(plan) = files.next() else {
            break;
        };
        spawn_extraction_worker(&mut workers, reader.clone(), plan);
    }

    while let Some(result) = workers.join_next().await {
        result.map_err(|error| {
            BackendError::Zip(format!("IPA extraction worker failed: {error}"))
        })??;
        completed += 1;
        report_extracting_progress(progress, completed, total);

        if let Some(plan) = files.next() {
            spawn_extraction_worker(&mut workers, reader.clone(), plan);
        }
    }

    Ok(())
}

struct ExtractionPlan {
    index: usize,
    name: String,
    output_path: PathBuf,
    unix_permissions: Option<u16>,
}

fn spawn_extraction_worker(
    workers: &mut JoinSet<BackendResult<()>>,
    reader: ExtractionReader,
    plan: ExtractionPlan,
) {
    workers.spawn(async move {
        let data = reader.read_entry(plan.index, &plan.name).await?;
        tokio::fs::write(&plan.output_path, data)
            .await
            .map_err(|source| BackendError::Io {
                action: "Extract IPA file",
                path: plan.output_path.clone(),
                source,
            })?;
        set_extracted_permissions(&plan.output_path, plan.unix_permissions)
    });
}

#[derive(Clone)]
enum ExtractionReader {
    FileSystem(ZipFileReader),
    Memory(MemoryZipFileReader),
}

impl ExtractionReader {
    async fn open(path: &Path) -> BackendResult<Self> {
        let metadata = tokio::fs::metadata(path)
            .await
            .map_err(|source| BackendError::Io {
                action: "Inspect IPA before extraction",
                path: path.to_path_buf(),
                source,
            })?;
        if metadata.len() <= IN_MEMORY_EXTRACTION_LIMIT {
            let data = tokio::fs::read(path)
                .await
                .map_err(|source| BackendError::Io {
                    action: "Read IPA for extraction",
                    path: path.to_path_buf(),
                    source,
                })?;
            let reader = MemoryZipFileReader::new(data)
                .await
                .map_err(|error| BackendError::Zip(format!("{}: {error}", path.display())))?;
            Ok(Self::Memory(reader))
        } else {
            let reader = ZipFileReader::new(path)
                .await
                .map_err(|error| BackendError::Zip(format!("{}: {error}", path.display())))?;
            Ok(Self::FileSystem(reader))
        }
    }

    fn file(&self) -> &async_zip::ZipFile {
        match self {
            Self::FileSystem(reader) => reader.file(),
            Self::Memory(reader) => reader.file(),
        }
    }

    async fn read_entry(&self, index: usize, label: &str) -> BackendResult<Vec<u8>> {
        match self {
            Self::FileSystem(reader) => read_entry(reader, index, label).await,
            Self::Memory(reader) => {
                let mut entry_reader =
                    reader.reader_without_entry(index).await.map_err(|error| {
                        BackendError::Zip(format!("Failed to read {label} from IPA: {error}"))
                    })?;
                let mut data = Vec::new();
                entry_reader.read_to_end(&mut data).await.map_err(|error| {
                    BackendError::Zip(format!("Failed to extract {label} from IPA: {error}"))
                })?;
                Ok(data)
            }
        }
    }
}

fn archive_worker_count(maximum: usize) -> usize {
    std::thread::available_parallelism()
        .map(|parallelism| parallelism.get())
        .unwrap_or(1)
        .clamp(1, maximum)
}

fn safe_zip_entry_path(name: &str) -> BackendResult<PathBuf> {
    if name.is_empty() || name.contains('\\') {
        return Err(unsafe_zip_path_error(name));
    }

    let mut result = PathBuf::new();
    for component in Path::new(name).components() {
        match component {
            Component::Normal(component) => result.push(component),
            _ => return Err(unsafe_zip_path_error(name)),
        }
    }
    if result.as_os_str().is_empty() {
        Err(unsafe_zip_path_error(name))
    } else {
        Ok(result)
    }
}

fn unsafe_zip_path_error(name: &str) -> BackendError {
    BackendError::Zip(format!("IPA contains unsafe entry path {name:?}."))
}

fn is_symlink_mode(mode: u16) -> bool {
    mode & 0o170000 == 0o120000
}

#[cfg(unix)]
fn set_extracted_permissions(path: &Path, mode: Option<u16>) -> BackendResult<()> {
    let Some(mode) = mode else {
        return Ok(());
    };
    let mode = mode & 0o7777;
    if mode == 0 {
        return Ok(());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(u32::from(mode))).map_err(|source| {
        BackendError::Io {
            action: "Restore extracted IPA permissions",
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn set_extracted_permissions(_: &Path, _: Option<u16>) -> BackendResult<()> {
    Ok(())
}

fn root_app_bundle(staging_root: &Path) -> BackendResult<PathBuf> {
    let payload = staging_root.join("Payload");
    let entries = fs::read_dir(&payload).map_err(|source| BackendError::Io {
        action: "Read extracted IPA Payload folder",
        path: payload.clone(),
        source,
    })?;
    let mut apps = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            entry
                .file_type()
                .ok()
                .filter(|kind| kind.is_dir())
                .and_then(|_| {
                    (path.extension().and_then(|value| value.to_str()) == Some("app"))
                        .then_some(path)
                })
        })
        .collect::<Vec<_>>();
    apps.sort();

    match apps.len() {
        1 => Ok(apps.remove(0)),
        0 => Err(BackendError::Zip(
            "IPA does not contain a root Payload/*.app bundle.".to_string(),
        )),
        count => Err(BackendError::Zip(format!(
            "IPA contains {count} root app bundles; exactly one is required."
        ))),
    }
}

fn patch_app_bundle(
    app_path: &Path,
    metadata: &AppMetadata,
    icon_override_path: Option<&Path>,
) -> BackendResult<()> {
    validate_metadata(metadata)?;
    let info_path = app_path.join("Info.plist");
    let mut info = match Value::from_file(&info_path).map_err(|error| {
        BackendError::Plist(format!("Failed to read {}: {error}", info_path.display()))
    })? {
        Value::Dictionary(info) => info,
        _ => {
            return Err(BackendError::Plist(format!(
                "{} is not a dictionary.",
                info_path.display()
            )));
        }
    };

    let old_executable = required_plist_string(&info, "CFBundleExecutable")?.to_string();
    validate_executable_name(&old_executable)?;
    validate_executable_name(&metadata.executable)?;
    if old_executable != metadata.executable {
        let old_path = app_path.join(&old_executable);
        let new_path = app_path.join(&metadata.executable);
        if new_path.exists() {
            return Err(BackendError::Message(format!(
                "Cannot rename the app executable to {} because that file already exists.",
                metadata.executable
            )));
        }
        fs::rename(&old_path, &new_path).map_err(|source| BackendError::Io {
            action: "Rename app executable",
            path: old_path,
            source,
        })?;
    }

    set_info_string(&mut info, "CFBundleIdentifier", &metadata.bundle_id);
    set_info_string(&mut info, "CFBundleDisplayName", &metadata.name);
    set_info_string(&mut info, "CFBundleName", &metadata.name);
    set_info_string(&mut info, "CFBundleShortVersionString", &metadata.version);
    set_info_string(&mut info, "CFBundleVersion", &metadata.build);
    set_info_string(&mut info, "CFBundleExecutable", &metadata.executable);
    set_info_string(&mut info, "MinimumOSVersion", &metadata.minimum_os);
    if metadata.supported_devices.is_empty() {
        info.remove("UIDeviceFamily");
    } else {
        info.insert(
            "UIDeviceFamily".to_string(),
            Value::Array(
                metadata
                    .supported_devices
                    .iter()
                    .map(|family| Value::Integer(device_family_id(*family).into()))
                    .collect(),
            ),
        );
    }

    if let Some(icon_path) = icon_override_path {
        patch_icon(app_path, &mut info, icon_path, &metadata.supported_devices)?;
    }

    Value::Dictionary(info)
        .to_file_binary(&info_path)
        .map_err(|error| {
            BackendError::Plist(format!("Failed to write {}: {error}", info_path.display()))
        })
}

fn patch_nested_bundle_identifiers(
    app_path: &Path,
    replacements: &BTreeMap<String, String>,
) -> BackendResult<()> {
    for entry in WalkDir::new(app_path).follow_links(false) {
        let entry = entry.map_err(|error| {
            BackendError::Message(format!(
                "Failed to inspect nested bundles in {}: {error}",
                app_path.display()
            ))
        })?;
        let info_path = entry.path();
        if !entry.file_type().is_file() || entry.file_name() != "Info.plist" {
            continue;
        }
        let mut info = match Value::from_file(info_path).map_err(|error| {
            BackendError::Plist(format!("Failed to read {}: {error}", info_path.display()))
        })? {
            Value::Dictionary(info) => info,
            _ => continue,
        };
        let Some(bundle_id) = plist_string(&info, "CFBundleIdentifier") else {
            continue;
        };
        let Some(replacement) = replacements.get(bundle_id) else {
            continue;
        };
        if replacement == bundle_id {
            continue;
        }
        info.insert(
            "CFBundleIdentifier".to_string(),
            Value::String(replacement.clone()),
        );
        Value::Dictionary(info)
            .to_file_binary(info_path)
            .map_err(|error| {
                BackendError::Plist(format!("Failed to write {}: {error}", info_path.display()))
            })?;
    }
    Ok(())
}

fn validate_metadata(metadata: &AppMetadata) -> BackendResult<()> {
    for (label, value) in [
        ("app name", metadata.name.as_str()),
        ("bundle identifier", metadata.bundle_id.as_str()),
        ("version", metadata.version.as_str()),
        ("build", metadata.build.as_str()),
        ("executable", metadata.executable.as_str()),
        ("minimum OS version", metadata.minimum_os.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(BackendError::Message(format!(
                "The {label} cannot be empty when signing."
            )));
        }
    }
    Ok(())
}

fn validate_executable_name(name: &str) -> BackendResult<()> {
    let mut components = Path::new(name).components();
    if matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none() {
        Ok(())
    } else {
        Err(BackendError::Message(format!(
            "The app executable name {name:?} must be a file name, not a path."
        )))
    }
}

fn set_info_string(info: &mut Dictionary, key: &str, value: &str) {
    info.insert(key.to_string(), Value::String(value.to_string()));
}

fn device_family_id(family: SupportedDeviceFamily) -> i64 {
    match family {
        SupportedDeviceFamily::IPhone => 1,
        SupportedDeviceFamily::IPad => 2,
        SupportedDeviceFamily::AppleTv => 3,
        SupportedDeviceFamily::AppleWatch => 4,
        SupportedDeviceFamily::Mac => 6,
    }
}

fn patch_icon(
    app_path: &Path,
    info: &mut Dictionary,
    icon_path: &Path,
    supported_devices: &[SupportedDeviceFamily],
) -> BackendResult<()> {
    if !icon_path.is_file() {
        return Err(BackendError::Message(format!(
            "The app icon override does not exist: {}",
            icon_path.display()
        )));
    }
    if !icon_path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("png"))
    {
        return Err(BackendError::Message(
            "The app icon override must be a PNG file.".to_string(),
        ));
    }

    write_icon_variants(app_path, icon_path)?;

    let supports_ipad = supported_devices.contains(&SupportedDeviceFamily::IPad);
    let supports_iphone = supported_devices.contains(&SupportedDeviceFamily::IPhone);
    let (primary_icon_name, primary_icon_names) = if supports_iphone || !supports_ipad {
        (IPHONE_PRIMARY_ICON_NAME, IPHONE_ICON_NAMES)
    } else {
        (IPAD_PRIMARY_ICON_NAME, IPAD_ICON_NAMES)
    };
    info.remove("CFBundleIconName");
    info.insert(
        "CFBundleIconFile".to_string(),
        Value::String(primary_icon_name.to_string()),
    );
    info.insert(
        "CFBundleIconFiles".to_string(),
        icon_file_names(primary_icon_names),
    );
    info.insert(
        "CFBundleIcons".to_string(),
        Value::Dictionary(icon_dictionary(primary_icon_names)),
    );
    if supports_ipad {
        info.insert(
            "CFBundleIconFiles~ipad".to_string(),
            icon_file_names(IPAD_ICON_NAMES),
        );
        info.insert(
            "CFBundleIcons~ipad".to_string(),
            Value::Dictionary(icon_dictionary(IPAD_ICON_NAMES)),
        );
    } else {
        info.remove("CFBundleIconFiles~ipad");
        info.remove("CFBundleIcons~ipad");
    }
    Ok(())
}

fn icon_file_names(names: &[&str]) -> Value {
    Value::Array(
        names
            .iter()
            .map(|name| Value::String((*name).to_string()))
            .collect(),
    )
}

fn icon_dictionary(names: &[&str]) -> Dictionary {
    let mut primary = Dictionary::new();
    primary.insert("CFBundleIconFiles".to_string(), icon_file_names(names));
    let mut icons = Dictionary::new();
    icons.insert(
        "CFBundlePrimaryIcon".to_string(),
        Value::Dictionary(primary),
    );
    icons
}

fn sign_staged_app(app_path: &Path, request: &IpaSigningRequest) -> BackendResult<()> {
    let root_profile_data = request
        .provisioning_profiles
        .get(&request.metadata.bundle_id)
        .ok_or_else(|| {
            BackendError::Message(format!(
                "No provisioning profile was downloaded for {}.",
                request.metadata.bundle_id
            ))
        })?;
    let root_profile = ProvisioningProfile::parse(root_profile_data).map_err(|error| {
        BackendError::Message(format!(
            "Failed to parse the downloaded provisioning profile: {error}"
        ))
    })?;
    validate_signing_profile(&root_profile, &request.metadata.bundle_id, request)?;

    let private_key_der = decode_private_key(&request.private_key_pem)?;
    let signer = RustCryptoCmsSigner::from_der(
        &private_key_der,
        &request.certificate_der,
        root_profile
            .certificate_chain_der()
            .iter()
            .map(Vec::as_slice),
    )
    .map_err(|error| {
        BackendError::Message(format!("Failed to prepare the code signer: {error}"))
    })?;
    let mut settings = BundleSigningSettings::new(
        request.team_id.clone(),
        root_profile.entitlements().clone(),
        Some(&signer),
    );
    settings.embedded_mobileprovisions_by_bundle_id = request
        .provisioning_profiles
        .iter()
        .map(|(bundle_id, data)| (bundle_id.clone(), data.as_slice()))
        .collect();
    for (bundle_id, data) in &request.provisioning_profiles {
        if bundle_id == &request.metadata.bundle_id {
            continue;
        }
        let profile = ProvisioningProfile::parse(data).map_err(|error| {
            BackendError::Message(format!(
                "Failed to parse the provisioning profile for {bundle_id}: {error}"
            ))
        })?;
        validate_signing_profile(&profile, bundle_id, request)?;
        settings
            .entitlements_by_bundle_id
            .insert(bundle_id.clone(), profile.entitlements().clone());
    }
    sign_bundle(app_path, &settings)
        .map_err(|error| BackendError::Message(format!("Failed to sign the app bundle: {error}")))
}

fn validate_signing_profile(
    profile: &ProvisioningProfile,
    bundle_id: &str,
    request: &IpaSigningRequest,
) -> BackendResult<()> {
    if profile.team_id() != request.team_id {
        return Err(BackendError::Message(format!(
            "The provisioning profile for {bundle_id} belongs to team {}, not selected team {}.",
            profile.team_id(),
            request.team_id
        )));
    }
    if !profile_contains_certificate(profile, &request.certificate_der) {
        return Err(BackendError::Message(format!(
            "The provisioning profile for {bundle_id} does not include the selected certificate. Refresh Developer Settings and try again."
        )));
    }

    let expected_identifier = if bundle_id
        .strip_prefix(&request.team_id)
        .is_some_and(|suffix| suffix.starts_with('.'))
    {
        bundle_id.to_string()
    } else {
        format!("{}.{bundle_id}", request.team_id)
    };
    let profile_identifier = profile
        .entitlements()
        .get("application-identifier")
        .and_then(Value::as_string)
        .ok_or_else(|| {
            BackendError::Message(format!(
                "The provisioning profile for {bundle_id} has no application identifier."
            ))
        })?;
    if profile_identifier != expected_identifier
        && !profile_identifier
            .strip_suffix('*')
            .is_some_and(|prefix| expected_identifier.starts_with(prefix))
    {
        return Err(BackendError::Message(format!(
            "Provisioning profile {profile_identifier} does not match bundle {bundle_id}."
        )));
    }
    Ok(())
}

fn profile_contains_certificate(profile: &ProvisioningProfile, certificate_der: &[u8]) -> bool {
    profile
        .plist()
        .get("DeveloperCertificates")
        .and_then(Value::as_array)
        .is_some_and(|certificates| {
            certificates
                .iter()
                .filter_map(Value::as_data)
                .any(|candidate| candidate == certificate_der)
        })
}

fn decode_private_key(data: &[u8]) -> BackendResult<Vec<u8>> {
    if !data.starts_with(b"-----BEGIN ") {
        return Ok(data.to_vec());
    }
    let (label, der) = pem_rfc7468::decode_vec(data).map_err(|error| {
        BackendError::Message(format!(
            "Failed to decode the managed PEM private key: {error}"
        ))
    })?;
    if matches!(label, "PRIVATE KEY" | "RSA PRIVATE KEY") {
        Ok(der)
    } else {
        Err(BackendError::Message(format!(
            "Unsupported managed private key PEM label {label:?}."
        )))
    }
}

async fn package_ipa(
    staging_root: &Path,
    output_path: &Path,
    progress: &mut impl FnMut(IpaSigningProgress),
) -> BackendResult<()> {
    let mut entries = WalkDir::new(staging_root)
        .follow_links(false)
        .into_iter()
        .skip(1)
        .map(|entry| {
            entry.map_err(|error| {
                BackendError::Zip(format!(
                    "Failed to enumerate staged IPA files under {}: {error}",
                    staging_root.display()
                ))
            })
        })
        .collect::<BackendResult<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.path().to_path_buf());

    let output = tokio::fs::File::create(output_path)
        .await
        .map_err(|source| BackendError::Io {
            action: "Create signed IPA archive",
            path: output_path.to_path_buf(),
            source,
        })?;
    let mut writer = ZipFileWriter::with_tokio(output);
    let total = entries.len();
    progress(IpaSigningProgress::Packaging {
        completed: 0,
        total,
    });

    let mut directories = Vec::new();
    let mut files = Vec::new();
    for entry in entries {
        let path = entry.path();
        let relative = path.strip_prefix(staging_root).map_err(|_| {
            BackendError::Zip(format!(
                "Failed to create a relative path for {}.",
                path.display()
            ))
        })?;
        let mut name = relative
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");
        let metadata = entry.metadata().map_err(|error| {
            BackendError::Zip(format!("Failed to inspect {}: {error}", path.display()))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(BackendError::Zip(format!(
                "Staged IPA contains unsupported symbolic link {}.",
                path.display()
            )));
        }

        if metadata.is_dir() {
            name.push('/');
            directories.push(PackageDirectory {
                path: path.to_path_buf(),
                name,
                unix_mode: zip_mode(&metadata, true),
            });
        } else if metadata.is_file() {
            files.push(PackageFilePlan {
                path: path.to_path_buf(),
                name,
                unix_mode: zip_mode(&metadata, false),
            });
        }
    }

    let mut completed = 0;
    for directory in directories {
        let builder = ZipEntryBuilder::new(directory.name.into(), Compression::Stored)
            .unix_permissions(directory.unix_mode);
        writer
            .write_entry_whole(builder, &[])
            .await
            .map_err(|error| {
                BackendError::Zip(format!("Failed to package {:?}: {error}", directory.path))
            })?;
        completed += 1;
        report_packaging_progress(progress, completed, total);
    }

    let mut files = files.into_iter();
    let mut workers = JoinSet::new();
    let concurrency = archive_worker_count(MAX_PACKAGING_WORKERS);
    for _ in 0..concurrency {
        let Some(plan) = files.next() else {
            break;
        };
        workers.spawn_blocking(move || prepare_zip_file(plan));
    }

    while let Some(result) = workers.join_next().await {
        let prepared = result.map_err(|error| {
            BackendError::Zip(format!("IPA packaging worker failed: {error}"))
        })??;
        writer
            .write_entry_whole_precompressed(prepared.entry, &prepared.data)
            .await
            .map_err(|error| {
                BackendError::Zip(format!(
                    "Failed to package {:?}: {error}",
                    prepared.source_path
                ))
            })?;
        completed += 1;
        report_packaging_progress(progress, completed, total);

        if let Some(plan) = files.next() {
            workers.spawn_blocking(move || prepare_zip_file(plan));
        }
    }

    let mut output = writer
        .close()
        .await
        .map_err(|error| BackendError::Zip(format!("Failed to finish signed IPA: {error}")))?
        .into_inner();
    output.flush().await.map_err(|source| BackendError::Io {
        action: "Flush signed IPA archive",
        path: output_path.to_path_buf(),
        source,
    })?;
    output.sync_all().await.map_err(|source| BackendError::Io {
        action: "Sync signed IPA archive",
        path: output_path.to_path_buf(),
        source,
    })
}

struct PackageDirectory {
    path: PathBuf,
    name: String,
    unix_mode: u16,
}

struct PackageFilePlan {
    path: PathBuf,
    name: String,
    unix_mode: u16,
}

struct PreparedZipFile {
    source_path: PathBuf,
    entry: ZipEntry,
    data: Vec<u8>,
}

fn prepare_zip_file(plan: PackageFilePlan) -> BackendResult<PreparedZipFile> {
    let source_data = fs::read(&plan.path).map_err(|source| BackendError::Io {
        action: "Read staged IPA file",
        path: plan.path.clone(),
        source,
    })?;
    let source_size = source_data.len() as u64;
    let crc32 = crc32fast::hash(&source_data);
    let preferred_compression = compression_for_path(&plan.path);
    let (compression, data) = if preferred_compression == Compression::Deflate {
        let mut encoder =
            DeflateEncoder::new(Vec::new(), FlateCompression::new(FAST_DEFLATE_LEVEL));
        encoder
            .write_all(&source_data)
            .map_err(|source| BackendError::Io {
                action: "Compress staged IPA file",
                path: plan.path.clone(),
                source,
            })?;
        let compressed = encoder.finish().map_err(|source| BackendError::Io {
            action: "Finish compressing staged IPA file",
            path: plan.path.clone(),
            source,
        })?;
        if compressed.len() < source_data.len() {
            (Compression::Deflate, compressed)
        } else {
            (Compression::Stored, source_data)
        }
    } else {
        (Compression::Stored, source_data)
    };
    let compressed_size = data.len() as u64;
    let entry = ZipEntryBuilder::new(plan.name.into(), compression)
        .unix_permissions(plan.unix_mode)
        .crc32(crc32)
        .uncompressed_size(source_size)
        .compressed_size(compressed_size)
        .build();

    Ok(PreparedZipFile {
        source_path: plan.path,
        entry,
        data,
    })
}

fn compression_for_path(path: &Path) -> Compression {
    let already_compressed = path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "7z" | "aac"
                    | "bz2"
                    | "car"
                    | "gif"
                    | "gz"
                    | "heic"
                    | "heif"
                    | "ipa"
                    | "jpeg"
                    | "jpg"
                    | "m4a"
                    | "m4v"
                    | "mov"
                    | "mp3"
                    | "mp4"
                    | "pdf"
                    | "png"
                    | "rar"
                    | "webp"
                    | "xz"
                    | "zip"
                    | "zst"
            )
        });
    if already_compressed {
        Compression::Stored
    } else {
        Compression::Deflate
    }
}

fn report_extracting_progress(
    progress: &mut impl FnMut(IpaSigningProgress),
    completed: usize,
    total: usize,
) {
    if should_report_item_progress(completed, total) {
        progress(IpaSigningProgress::Extracting { completed, total });
    }
}

fn report_packaging_progress(
    progress: &mut impl FnMut(IpaSigningProgress),
    completed: usize,
    total: usize,
) {
    if should_report_item_progress(completed, total) {
        progress(IpaSigningProgress::Packaging { completed, total });
    }
}

fn should_report_item_progress(completed: usize, total: usize) -> bool {
    completed == 0
        || completed >= total
        || (completed.saturating_mul(100) / total.max(1))
            != (completed.saturating_sub(1).saturating_mul(100) / total.max(1))
}

#[cfg(unix)]
fn zip_mode(metadata: &fs::Metadata, _: bool) -> u16 {
    (metadata.permissions().mode() & 0xffff) as u16
}

#[cfg(not(unix))]
fn zip_mode(_: &fs::Metadata, directory: bool) -> u16 {
    if directory {
        0o755
    } else {
        0o644
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signing_metadata(executable: &str) -> AppMetadata {
        AppMetadata {
            name: "Patched App".to_string(),
            bundle_id: "com.example.patched".to_string(),
            version: "2.0".to_string(),
            build: "42".to_string(),
            executable: executable.to_string(),
            minimum_os: "16.0".to_string(),
            supported_devices: vec![SupportedDeviceFamily::IPhone, SupportedDeviceFamily::IPad],
        }
    }

    fn write_test_app(app_path: &Path, executable: &str) {
        fs::create_dir_all(app_path).unwrap();
        fs::write(app_path.join(executable), b"executable").unwrap();
        let mut info = Dictionary::new();
        info.insert(
            "CFBundleIdentifier".to_string(),
            Value::String("com.example.original".to_string()),
        );
        info.insert(
            "CFBundleExecutable".to_string(),
            Value::String(executable.to_string()),
        );
        Value::Dictionary(info)
            .to_file_binary(app_path.join("Info.plist"))
            .unwrap();
    }

    #[test]
    fn info_plist_paths_require_payload_app_prefix() {
        assert!(is_app_info_plist("Payload/App.app/Info.plist"));
        assert!(!is_app_info_plist("Payload/Nested/App.app/Info.plist"));
        assert!(!is_app_info_plist("App.app/Info.plist"));
        assert!(!is_app_info_plist("Payload/App.app/Other.plist"));
    }

    #[test]
    fn nested_signable_bundle_paths_include_extensions_and_nested_apps() {
        let root = "Payload/App.app/";

        assert_eq!(
            nested_signable_bundle_kind("Payload/App.app/PlugIns/Widget.appex/Info.plist", root),
            Some(NestedBundleKind::AppExtension)
        );
        assert_eq!(
            nested_signable_bundle_kind("Payload/App.app/Watch/WatchApp.app/Info.plist", root),
            Some(NestedBundleKind::App)
        );
        assert_eq!(
            nested_signable_bundle_kind(
                "Payload/App.app/Frameworks/Example.framework/Info.plist",
                root
            ),
            None
        );
        assert_eq!(
            nested_signable_bundle_kind("Payload/App.app/Info.plist", root),
            None
        );
    }

    #[test]
    fn stripping_extensions_preserves_nested_apps_and_frameworks() {
        let temp = tempfile::tempdir().unwrap();
        let app_path = temp.path().join("Payload").join("Test.app");
        let extension_path = app_path.join("PlugIns").join("Widget.appex");
        let nested_app_path = app_path.join("Watch").join("WatchApp.app");
        let nested_extension_path = nested_app_path.join("PlugIns").join("Companion.appex");
        let framework_path = app_path.join("Frameworks").join("Example.framework");
        for path in [
            &extension_path,
            &nested_app_path,
            &nested_extension_path,
            &framework_path,
        ] {
            fs::create_dir_all(path).unwrap();
            fs::write(path.join("content"), b"test").unwrap();
        }

        strip_app_extensions(&app_path).unwrap();

        assert!(!extension_path.exists());
        assert!(!nested_extension_path.exists());
        assert!(nested_app_path.exists());
        assert!(framework_path.exists());
    }

    #[test]
    fn required_plist_string_reports_missing_key() {
        let mut info = Dictionary::new();
        info.insert(
            "CFBundleIdentifier".to_string(),
            Value::String("com.example.app".to_string()),
        );

        assert_eq!(
            required_plist_string(&info, "CFBundleIdentifier").unwrap(),
            "com.example.app"
        );
        assert_eq!(
            required_plist_string(&info, "CFBundleName")
                .unwrap_err()
                .user_message(),
            "Failed to parse plist data: IPA Info.plist is missing string key CFBundleName."
        );
    }

    #[test]
    fn item_progress_is_sampled_at_percent_boundaries_and_completion() {
        assert!(should_report_item_progress(0, 1_000));
        assert!(!should_report_item_progress(1, 1_000));
        assert!(should_report_item_progress(10, 1_000));
        assert!(should_report_item_progress(1_000, 1_000));
    }

    #[test]
    fn packaging_skips_deflate_for_already_compressed_formats() {
        for path in ["Icon.PNG", "Assets.car", "Video.mp4", "Nested/archive.zip"] {
            assert_eq!(compression_for_path(Path::new(path)), Compression::Stored);
        }
        for path in ["Info.plist", "Executable", "Framework.dylib"] {
            assert_eq!(compression_for_path(Path::new(path)), Compression::Deflate);
        }
    }

    #[test]
    fn supported_device_family_values_are_normalized() {
        let mut info = Dictionary::new();
        info.insert(
            "UIDeviceFamily".to_string(),
            Value::Array(vec![
                Value::Integer(2.into()),
                Value::Integer(1.into()),
                Value::Integer(2.into()),
                Value::Integer(99.into()),
            ]),
        );

        assert_eq!(
            supported_devices(&info),
            vec![SupportedDeviceFamily::IPhone, SupportedDeviceFamily::IPad]
        );
    }

    #[test]
    fn entitlement_values_are_mapped_without_ui_types() {
        let mut entitlements = Dictionary::new();
        entitlements.insert(
            "application-identifier".to_string(),
            Value::String("TEAM.com.example.app".to_string()),
        );
        entitlements.insert("get-task-allow".to_string(), Value::Boolean(true));

        let mapped = entitlements_from_dictionary(&entitlements);

        assert!(mapped.iter().any(|entitlement| {
            entitlement.key == "application-identifier"
                && entitlement.value == EntitlementValue::String("TEAM.com.example.app".into())
        }));
        assert!(mapped.iter().any(|entitlement| {
            entitlement.key == "get-task-allow"
                && entitlement.value == EntitlementValue::Boolean(true)
        }));
    }

    #[test]
    fn zip_entry_paths_reject_traversal_and_platform_separators() {
        assert_eq!(
            safe_zip_entry_path("Payload/App.app/Info.plist").unwrap(),
            PathBuf::from("Payload/App.app/Info.plist")
        );
        for path in [
            "../outside",
            "Payload/../../outside",
            "/absolute/path",
            "Payload\\..\\outside",
        ] {
            assert!(safe_zip_entry_path(path).is_err(), "accepted {path}");
        }
    }

    #[test]
    fn plist_patching_updates_metadata_and_renames_executable() {
        let temp = tempfile::tempdir().unwrap();
        let app_path = temp.path().join("Payload").join("Test.app");
        write_test_app(&app_path, "OriginalExecutable");

        patch_app_bundle(&app_path, &signing_metadata("PatchedExecutable"), None).unwrap();

        assert!(!app_path.join("OriginalExecutable").exists());
        assert!(app_path.join("PatchedExecutable").exists());
        let info = Value::from_file(app_path.join("Info.plist"))
            .unwrap()
            .into_dictionary()
            .unwrap();
        assert_eq!(
            info.get("CFBundleIdentifier").and_then(Value::as_string),
            Some("com.example.patched")
        );
        assert_eq!(
            info.get("CFBundleDisplayName").and_then(Value::as_string),
            Some("Patched App")
        );
        assert_eq!(
            info.get("CFBundleExecutable").and_then(Value::as_string),
            Some("PatchedExecutable")
        );
        assert_eq!(
            info.get("UIDeviceFamily")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(2)
        );
    }

    #[test]
    fn nested_bundle_identifiers_are_patched_from_provisioning_map() {
        let temp = tempfile::tempdir().unwrap();
        let app_path = temp.path().join("Payload").join("Test.app");
        let extension_path = app_path.join("PlugIns").join("Widget.appex");
        let framework_path = app_path.join("Frameworks").join("Example.framework");
        for (path, bundle_id) in [
            (&extension_path, "com.example.app.widget"),
            (&framework_path, "com.example.framework"),
        ] {
            fs::create_dir_all(path).unwrap();
            let mut info = Dictionary::new();
            info.insert(
                "CFBundleIdentifier".to_string(),
                Value::String(bundle_id.to_string()),
            );
            Value::Dictionary(info)
                .to_file_binary(path.join("Info.plist"))
                .unwrap();
        }

        patch_nested_bundle_identifiers(
            &app_path,
            &BTreeMap::from([(
                "com.example.app.widget".to_string(),
                "com.example.app.TEAM.widget".to_string(),
            )]),
        )
        .unwrap();

        let extension_info = Value::from_file(extension_path.join("Info.plist"))
            .unwrap()
            .into_dictionary()
            .unwrap();
        let framework_info = Value::from_file(framework_path.join("Info.plist"))
            .unwrap()
            .into_dictionary()
            .unwrap();
        assert_eq!(
            plist_string(&extension_info, "CFBundleIdentifier"),
            Some("com.example.app.TEAM.widget")
        );
        assert_eq!(
            plist_string(&framework_info, "CFBundleIdentifier"),
            Some("com.example.framework")
        );
    }

    #[test]
    fn icon_override_generates_variants_and_updates_info_plist() {
        let temp = tempfile::tempdir().unwrap();
        let app_path = temp.path().join("Payload").join("Test.app");
        write_test_app(&app_path, "TestExecutable");
        let icon_path = temp.path().join("override.png");
        image::RgbaImage::from_pixel(180, 180, image::Rgba([20, 40, 80, 255]))
            .save(&icon_path)
            .unwrap();

        patch_app_bundle(
            &app_path,
            &signing_metadata("TestExecutable"),
            Some(&icon_path),
        )
        .unwrap();

        assert!(app_path.join("SuperSideloaderIcon60@3x.png").exists());
        assert!(app_path.join("SuperSideloaderIcon76@2x.png").exists());
        assert!(app_path.join("SuperSideloaderIcon83_5@2x.png").exists());
        let info = Value::from_file(app_path.join("Info.plist"))
            .unwrap()
            .into_dictionary()
            .unwrap();
        assert_eq!(
            info.get("CFBundleIconFiles")
                .and_then(Value::as_array)
                .and_then(|files| files.first())
                .and_then(Value::as_string),
            Some("SuperSideloaderIcon20")
        );
        assert_eq!(
            info.get("CFBundleIconFiles")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(IPHONE_ICON_NAMES.len())
        );
        assert_eq!(
            info.get("CFBundleIconFiles~ipad")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(IPAD_ICON_NAMES.len())
        );
        assert!(info.contains_key("CFBundleIcons~ipad"));
    }

    #[tokio::test]
    async fn ipa_packaging_round_trips_files_permissions_and_compression() {
        let temp = tempfile::tempdir().unwrap();
        let staging = temp.path().join("staging");
        let executable = staging.join("Payload/Test.app/TestExecutable");
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::write(&executable, b"executable").unwrap();
        let text = executable.parent().unwrap().join("Config.txt");
        let text_contents = vec![b'A'; 64 * 1024];
        fs::write(&text, &text_contents).unwrap();
        let png = executable.parent().unwrap().join("Icon.png");
        let png_contents = b"already-compressed-image-data";
        fs::write(&png, png_contents).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();

        let ipa_path = temp.path().join("signed.ipa");
        let mut progress_events = Vec::new();
        package_ipa(&staging, &ipa_path, &mut |event| {
            progress_events.push(event)
        })
        .await
        .unwrap();

        assert!(matches!(
            progress_events.first(),
            Some(IpaSigningProgress::Packaging { completed: 0, .. })
        ));
        assert!(matches!(
            progress_events.last(),
            Some(IpaSigningProgress::Packaging { completed, total }) if completed == total
        ));

        let reader = ZipFileReader::new(&ipa_path).await.unwrap();
        let find_entry = |name: &str| {
            reader
                .file()
                .entries()
                .iter()
                .find(|entry| entry_name(entry) == Some(name))
                .unwrap()
        };
        let entry = find_entry("Payload/Test.app/TestExecutable");
        #[cfg(unix)]
        assert_ne!(entry.unix_permissions().unwrap_or_default() & 0o111, 0);
        assert_eq!(
            find_entry("Payload/Test.app/Config.txt").compression(),
            Compression::Deflate
        );
        assert_eq!(
            find_entry("Payload/Test.app/Icon.png").compression(),
            Compression::Stored
        );

        let extracted = temp.path().join("round-trip");
        fs::create_dir(&extracted).unwrap();
        let mut extraction_progress = Vec::new();
        extract_ipa(&ipa_path, &extracted, &mut |event| {
            extraction_progress.push(event)
        })
        .await
        .unwrap();
        assert_eq!(
            fs::read(extracted.join("Payload/Test.app/TestExecutable")).unwrap(),
            b"executable"
        );
        assert_eq!(
            fs::read(extracted.join("Payload/Test.app/Config.txt")).unwrap(),
            text_contents
        );
        assert_eq!(
            fs::read(extracted.join("Payload/Test.app/Icon.png")).unwrap(),
            png_contents
        );
        assert!(matches!(
            extraction_progress.first(),
            Some(IpaSigningProgress::Extracting { completed: 0, .. })
        ));
        assert!(matches!(
            extraction_progress.last(),
            Some(IpaSigningProgress::Extracting { completed, total }) if completed == total
        ));
        #[cfg(unix)]
        assert_ne!(
            fs::metadata(extracted.join("Payload/Test.app/TestExecutable"))
                .unwrap()
                .permissions()
                .mode()
                & 0o111,
            0
        );
    }
}
