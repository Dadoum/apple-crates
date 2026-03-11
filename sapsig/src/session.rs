//! SAP (Secure Authentication Protocol) session management for FairPlay signing.
//!
//! Extracted from xas_call.rs to share between CLI and HTTP server binaries.
#![allow(dead_code)]
#![allow(unsafe_op_in_unsafe_fn)]

use anyhow::{Context, Result, anyhow, bail};
use goblin::elf::Elf;
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
use std::cell::UnsafeCell;
use std::collections::HashSet;
use std::env;
use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};

use crate::elf_loader::{LoadedLibrary, clear_registered_libraries, install_wx_signal_handler};
use crate::hooks;

// ── Symbol constants ──

pub const SYM_LOAD_DEPS: &str = "kq56gsgHG6";
pub const SYM_MESCAL_SIGN_STRING: &str = "_ZN17storeservicescore6Mescal4signERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE";
pub const SYM_MESCAL_SIGN_DATA: &str =
    "_ZN17storeservicescore6Mescal4signERKNSt6__ndk110shared_ptrIN13mediaplatform4DataEEE";
pub const SYM_MESCAL_HEADER_DATA: &str = "_ZN17storeservicescore26MescalHeaderStringWithDataERKNSt6__ndk110shared_ptrIN13mediaplatform4DataEEE";
pub const SYM_FC3: &str = "Fc3vhtJDvr";
pub const SYM_SAP_INIT: &str = "cp2g1b9ro";
pub const SYM_SAP_EXCHANGE: &str = "Mib5yocT";
pub const SYM_SAP_TEARDOWN: &str = "IPaI1oem5iL";
pub const SYM_MESCAL_CTOR_DEFAULT: &str = "_ZN17storeservicescore6MescalC1Ev";
pub const SYM_MESCAL_DTOR: &str = "_ZN17storeservicescore6MescalD2Ev";
pub const SYM_MESCAL_VTABLE: &str = "_ZTVN17storeservicescore6MescalE";
pub const SYM_NDK_STRING_DTOR: &str =
    "_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED2Ev";
pub const SYM_REQUEST_CONTEXT_CTOR_DEFAULT: &str = "_ZN17storeservicescore14RequestContextC1Ev";
pub const SYM_REQUEST_CONTEXT_CTOR_ALT: &str = "_ZN17storeservicescore14RequestContextC2Ev";
pub const SYM_REQUEST_CONTEXT_MESCAL: &str = "_ZN17storeservicescore14RequestContext6mescalEv";
pub const SYM_REQUEST_CONTEXT_FAIRPLAY: &str = "_ZN17storeservicescore14RequestContext8fairPlayEv";
pub const SYM_MP_DATA_CTOR_FROM_BYTES: &str = "_ZN13mediaplatform4DataC1EPKvmb";
pub const SYM_MP_DATA_CTOR_DEFAULT: &str = "_ZN13mediaplatform4DataC1Ev";
pub const SYM_MP_DATA_DTOR: &str = "_ZN13mediaplatform4DataD1Ev";
pub const SYM_MP_DATA_BYTES: &str = "_ZNK13mediaplatform4Data5bytesEv";
pub const SYM_MP_DATA_LENGTH: &str = "_ZNK13mediaplatform4Data6lengthEv";

pub const DEFAULT_PRELOAD_LIBS: &[&str] = &[
    "libCoreFoundation.so",
    "libmediaplatform.so",
    "libCoreADI.so",
    "libCoreFP.so",
];
const DEFAULT_SAP_VERSION: u32 = 0xC8;

// ── Environment helpers ──

pub fn env_flag(name: &str) -> bool {
    env::var(name)
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn env_default_true(name: &str) -> bool {
    env::var(name)
        .ok()
        .map(|v| {
            let v = v.to_ascii_lowercase();
            !(v == "0" || v == "false" || v == "off")
        })
        .unwrap_or(true)
}

pub fn env_default_false(name: &str) -> bool {
    env::var(name)
        .ok()
        .map(|v| {
            let v = v.to_ascii_lowercase();
            v == "1" || v == "true" || v == "on"
        })
        .unwrap_or(false)
}

pub fn env_usize(name: &str, default: usize) -> usize {
    let Some(raw) = env::var(name).ok() else {
        return default;
    };
    parse_env_usize_value(&raw).unwrap_or(default)
}

pub fn parse_env_usize_value(raw: &str) -> Option<usize> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if raw.eq_ignore_ascii_case("null")
        || raw.eq_ignore_ascii_case("none")
        || raw.eq_ignore_ascii_case("nil")
    {
        return Some(0);
    }
    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        usize::from_str_radix(hex, 16).ok()
    } else {
        raw.parse::<usize>().ok()
    }
}

pub fn env_opt_usize(name: &str) -> Option<usize> {
    env::var(name)
        .ok()
        .and_then(|raw| parse_env_usize_value(&raw))
}

// ── Android TLS guard ──

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
thread_local! {
    static XAS_ANDROID_TLS: UnsafeCell<[u8; 0x100]> = const { UnsafeCell::new([0u8; 0x100]) };
}

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
#[inline]
unsafe fn read_tpidr_el0() -> usize {
    let value: usize;
    core::arch::asm!("mrs {value}, tpidr_el0", value = out(reg) value, options(nostack, preserves_flags));
    value
}

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
#[inline]
unsafe fn write_tpidr_el0(value: usize) {
    core::arch::asm!("msr tpidr_el0, {value}", value = in(reg) value, options(nostack, preserves_flags));
}

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
pub fn with_android_tls_guard<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    if env_flag("XAS_TLS_TRACE") {
        eprintln!("[tls] guard enter");
    }

    if !env::var("XAS_ANDROID_TLS")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true)
    {
        return f();
    }

    struct Restore(usize);

    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                write_tpidr_el0(self.0);
            }
        }
    }

    XAS_ANDROID_TLS.with(|tls| unsafe {
        let raw = (*tls.get()).as_mut_ptr();
        let raw_u = raw as usize;

        *(raw.add(0x00) as *mut usize) = raw_u;
        *(raw.add(0x08) as *mut usize) = raw_u;
        *(raw.add(0x10) as *mut usize) = raw_u;
        *(raw.add(0x28) as *mut usize) = 0x5a5a_5a5a_1b1b_1b1busize;

        let previous = read_tpidr_el0();
        write_tpidr_el0(raw_u);
        if env_flag("XAS_TLS_TRACE") {
            let current = read_tpidr_el0();
            eprintln!(
                "[tls] tpidr_el0 switch: prev={:#x} now={:#x} tls_base={:#x}",
                previous, current, raw_u
            );
        }
        let _restore = Restore(previous);
        f()
    })
}

#[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
#[inline]
pub fn with_android_tls_guard<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    f()
}

// ── FairPlay SAP protocol call wrappers ──

/// Call cp2g1b9ro (FairPlaySAPInit)
/// Signature: cp2g1b9ro(ctx_out, hwinfo_ptr) -> i32
#[cfg(target_arch = "aarch64")]
pub unsafe fn call_sap_init_cpp(fn_addr: usize, ctx_out: *mut u64, hwinfo: *const u8) -> i32 {
    with_android_tls_guard(|| {
        use core::arch::asm;
        let mut ret: u64;
        asm!(
            "blr x16",
            in("x16") fn_addr,
            in("x0") ctx_out,
            in("x1") hwinfo,
            lateout("x0") ret,
            clobber_abi("C"),
        );
        ret as i32
    })
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn call_sap_init_cpp(fn_addr: usize, ctx_out: *mut u64, hwinfo: *const u8) -> i32 {
    let f: extern "C" fn(*mut u64, *const u8) -> i32 = std::mem::transmute(fn_addr);
    f(ctx_out, hwinfo)
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
pub unsafe fn call_sap_init_cpp(_fn_addr: usize, _ctx_out: *mut u64, _hwinfo: *const u8) -> i32 {
    -1
}

/// Call Mib5yocT (FairPlaySAPExchange) — 8 arguments
#[cfg(target_arch = "aarch64")]
pub unsafe fn call_sap_exchange_cpp(
    fn_addr: usize,
    version: u32,
    hwinfo: *const u8,
    ctx: u64,
    input_buf: *const u8,
    input_len: u32,
    out_buf_ptr: *mut *mut u8,
    out_len_ptr: *mut u64,
    rc_ptr: *mut i32,
) -> i32 {
    with_android_tls_guard(|| {
        use core::arch::asm;
        let mut ret: u64;
        asm!(
            "blr x16",
            in("x16") fn_addr,
            in("x0") version as u64,
            in("x1") hwinfo,
            in("x2") ctx,
            in("x3") input_buf,
            in("x4") input_len as u64,
            in("x5") out_buf_ptr,
            in("x6") out_len_ptr,
            in("x7") rc_ptr,
            lateout("x0") ret,
            clobber_abi("C"),
        );
        ret as i32
    })
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn call_sap_exchange_cpp(
    fn_addr: usize,
    version: u32,
    hwinfo: *const u8,
    ctx: u64,
    input_buf: *const u8,
    input_len: u32,
    out_buf_ptr: *mut *mut u8,
    out_len_ptr: *mut u64,
    rc_ptr: *mut i32,
) -> i32 {
    let f: extern "C" fn(
        u32,
        *const u8,
        u64,
        *const u8,
        u32,
        *mut *mut u8,
        *mut u64,
        *mut i32,
    ) -> i32 = std::mem::transmute(fn_addr);
    f(
        version,
        hwinfo,
        ctx,
        input_buf,
        input_len,
        out_buf_ptr,
        out_len_ptr,
        rc_ptr,
    )
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
pub unsafe fn call_sap_exchange_cpp(
    _fn_addr: usize,
    _version: u32,
    _hwinfo: *const u8,
    _ctx: u64,
    _input_buf: *const u8,
    _input_len: u32,
    _out_buf_ptr: *mut *mut u8,
    _out_len_ptr: *mut u64,
    _rc_ptr: *mut i32,
) -> i32 {
    -1
}

/// Call Fc3vhtJDvr (FairPlaySAPSign) — 5 arguments
#[cfg(target_arch = "aarch64")]
pub unsafe fn call_sap_sign_cpp(
    fn_addr: usize,
    ctx: u64,
    input_buf: *const u8,
    input_len: u64,
    out_ptr_ptr: *mut *mut u8,
    out_len_ptr: *mut u64,
) -> i32 {
    with_android_tls_guard(|| {
        use core::arch::asm;
        let mut ret: u64;
        asm!(
            "blr x16",
            in("x16") fn_addr,
            in("x0") ctx,
            in("x1") input_buf,
            in("x2") input_len,
            in("x3") out_ptr_ptr,
            in("x4") out_len_ptr,
            lateout("x0") ret,
            clobber_abi("C"),
        );
        ret as i32
    })
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn call_sap_sign_cpp(
    fn_addr: usize,
    ctx: u64,
    input_buf: *const u8,
    input_len: u64,
    out_ptr_ptr: *mut *mut u8,
    out_len_ptr: *mut u64,
) -> i32 {
    let f: extern "C" fn(u64, *const u8, u64, *mut *mut u8, *mut u64) -> i32 =
        std::mem::transmute(fn_addr);
    f(ctx, input_buf, input_len, out_ptr_ptr, out_len_ptr)
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
pub unsafe fn call_sap_sign_cpp(
    _fn_addr: usize,
    _ctx: u64,
    _input_buf: *const u8,
    _input_len: u64,
    _out_ptr_ptr: *mut *mut u8,
    _out_len_ptr: *mut u64,
) -> i32 {
    -1
}

/// Call IPaI1oem5iL (FairPlaySAPTeardown)
#[cfg(target_arch = "aarch64")]
pub unsafe fn call_sap_teardown_cpp(fn_addr: usize, ctx: u64) -> i32 {
    with_android_tls_guard(|| {
        use core::arch::asm;
        let mut ret: u64;
        asm!(
            "blr x16",
            in("x16") fn_addr,
            in("x0") ctx,
            lateout("x0") ret,
            clobber_abi("C"),
        );
        ret as i32
    })
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn call_sap_teardown_cpp(fn_addr: usize, ctx: u64) -> i32 {
    let f: extern "C" fn(u64) -> i32 = std::mem::transmute(fn_addr);
    f(ctx)
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
pub unsafe fn call_sap_teardown_cpp(_fn_addr: usize, _ctx: u64) -> i32 {
    -1
}

// ── Preload helpers ──

pub fn normalize_path_key(path: &Path) -> String {
    if let Ok(canonical) = path.canonicalize() {
        canonical.to_string_lossy().to_ascii_lowercase()
    } else {
        path.to_string_lossy().to_ascii_lowercase()
    }
}

pub fn resolve_preload_path(native_lib_dir: &Path, name: &str) -> PathBuf {
    let p = Path::new(name);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        let direct = native_lib_dir.join(p);
        if direct.exists() {
            return direct;
        }
        let arm64_variant = native_lib_dir.join("arm64-v8a").join(p);
        if arm64_variant.exists() {
            return arm64_variant;
        }
        direct
    }
}

pub fn parse_dt_needed(path: &Path) -> Vec<String> {
    let Ok(bytes) = fs::read(path) else {
        return Vec::new();
    };
    let Ok(elf) = Elf::parse(&bytes) else {
        return Vec::new();
    };
    elf.libraries
        .iter()
        .map(|name| (*name).to_string())
        .collect()
}

pub fn preload_dependency_recursive(
    dep_path: &Path,
    native_lib_dir: &Path,
    target_key: &str,
    strict: bool,
    recursive: bool,
    loaded_keys: &mut HashSet<String>,
    loading_keys: &mut HashSet<String>,
    loaded: &mut Vec<LoadedLibrary>,
) -> Result<()> {
    let key = normalize_path_key(dep_path);
    if key == target_key {
        return Ok(());
    }
    if loaded_keys.contains(&key) {
        return Ok(());
    }
    if loading_keys.contains(&key) {
        return Ok(());
    }

    if !dep_path.exists() {
        let message = format!("Preload dependency not found: {}", dep_path.display());
        if strict {
            bail!("{message}");
        }
        eprintln!("Warning: {message}");
        return Ok(());
    }

    loading_keys.insert(key.clone());

    if recursive {
        for needed in parse_dt_needed(dep_path) {
            let child_path = resolve_preload_path(native_lib_dir, &needed);
            if !child_path.exists() {
                continue;
            }
            preload_dependency_recursive(
                &child_path,
                native_lib_dir,
                target_key,
                strict,
                recursive,
                loaded_keys,
                loading_keys,
                loaded,
            )?;
        }
    }

    match LoadedLibrary::load(dep_path) {
        Ok(lib) => {
            println!("Preloaded dependency: {}", dep_path.display());
            loaded.push(lib);
            loaded_keys.insert(key.clone());
        }
        Err(err) => {
            loading_keys.remove(&key);
            if strict {
                return Err(err).with_context(|| {
                    format!("Failed to preload dependency {}", dep_path.display())
                });
            }
            eprintln!("Warning: failed to preload {}: {}", dep_path.display(), err);
            return Ok(());
        }
    }

    loading_keys.remove(&key);
    Ok(())
}

pub fn preload_dependency_libraries(
    target_so_path: &Path,
    native_lib_dir: &Path,
) -> Result<Vec<LoadedLibrary>> {
    let strict = false;
    let recursive = true;
    let target_key = normalize_path_key(target_so_path);
    let mut loaded = Vec::new();
    let mut loaded_keys = HashSet::new();
    let mut loading_keys = HashSet::new();

    for name in DEFAULT_PRELOAD_LIBS {
        let dep_path = resolve_preload_path(native_lib_dir, name);
        preload_dependency_recursive(
            &dep_path,
            native_lib_dir,
            &target_key,
            strict,
            recursive,
            &mut loaded_keys,
            &mut loading_keys,
            &mut loaded,
        )?;
    }

    Ok(loaded)
}

// ── StoreServicesCore ──

pub struct StoreServicesCore {
    pub lib: LoadedLibrary,
    pub _deps: Vec<LoadedLibrary>,
    pub load_deps_addr: usize,
}

impl StoreServicesCore {
    pub fn load(so_path: &Path, native_lib_dir: &Path) -> Result<Self> {
        clear_registered_libraries();

        hooks::setup_hooks();
        if env_flag("XAS_HOOK_TRACE") {
            let hooks_guard = hooks::GLOBAL_HOOKS.lock().unwrap();
            for name in [
                "_ZNK13mediaplatform4Data5bytesEv",
                "_ZNK13mediaplatform4Data6lengthEv",
                "_ZN13mediaplatform12Base64EncodeEPK8__CFData",
                "CFDataCreateWithBytesNoCopy",
                "CFStringGetLength",
                "CFStringGetMaximumSizeForEncoding",
                "CFStringGetCString",
                "CFRelease",
            ] {
                if let Some(addr) = hooks_guard.get(name) {
                    eprintln!("[hook-map] {name} => {addr:#x}");
                } else {
                    eprintln!("[hook-map] {name} => <missing>");
                }
            }
        }

        let deps = preload_dependency_libraries(so_path, native_lib_dir)?;
        let lib = LoadedLibrary::load(so_path)
            .with_context(|| format!("Failed to load {}", so_path.display()))?;

        let load_deps_addr = lib
            .get_symbol(SYM_LOAD_DEPS)
            .ok_or_else(|| anyhow!("Symbol not found: {}", SYM_LOAD_DEPS))?;

        Ok(Self {
            lib,
            _deps: deps,
            load_deps_addr,
        })
    }

    pub fn bootstrap(&self, native_lib_dir: &Path) -> Result<i32> {
        let dir_str = native_lib_dir
            .canonicalize()
            .with_context(|| format!("Invalid path: {}", native_lib_dir.display()))?
            .to_str()
            .ok_or_else(|| anyhow!("Path is not valid UTF-8"))?
            .to_string();

        let c_path = CString::new(dir_str).context("Path contains null byte")?;

        let load_deps: extern "C" fn(*const i8) -> i32 =
            unsafe { std::mem::transmute(self.load_deps_addr) };

        let result = with_android_tls_guard(|| load_deps(c_path.as_ptr()));
        Ok(result)
    }

    pub fn get_symbol(&self, name: &str) -> Option<usize> {
        self.lib.get_symbol(name)
    }
}

// ── HTTP / crypto helpers ──

/// Build the 24-byte FairPlay hardware info block from a hardware identifier.
pub(crate) fn build_hwinfo_from_id(hardware_id: &[u8]) -> [u8; 24] {
    let mut hwinfo = [0u8; 24];
    let id_len = hardware_id.len().min(20) as u32;
    hwinfo[0..4].copy_from_slice(&id_len.to_le_bytes());
    hwinfo[4..4 + id_len as usize].copy_from_slice(&hardware_id[..id_len as usize]);
    hwinfo
}

/// Get a stable-ish hardware ID for FairPlayHwInfo.
pub fn get_hardware_id() -> Vec<u8> {
    let mut id = vec![0x02u8; 6];
    if let Ok(hostname) = env::var("HOSTNAME").or_else(|_| env::var("HOST")) {
        let mut hash: u32 = 5381;
        for b in hostname.bytes() {
            hash = hash.wrapping_mul(33).wrapping_add(b as u32);
        }
        id[2] = (hash >> 24) as u8;
        id[3] = (hash >> 16) as u8;
        id[4] = (hash >> 8) as u8;
        id[5] = hash as u8;
    } else {
        for b in id.iter_mut().skip(1) {
            *b = rand::random();
        }
    }
    id
}

pub(crate) fn encode_sap_setup_request_body(client_data: &[u8]) -> Result<String> {
    use base64::Engine;

    let b64_data = base64::engine::general_purpose::STANDARD.encode(client_data);

    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>sign-sap-setup-buffer</key>
	<data>{}</data>
</dict>
</plist>"#,
        b64_data
    ))
}

pub(crate) fn parse_sap_setup_response_body(resp_bytes: &[u8]) -> Result<Vec<u8>> {
    let resp_plist: plist::Value =
        plist::from_bytes(resp_bytes).context("Failed to parse response plist")?;

    let dict = resp_plist
        .as_dictionary()
        .ok_or_else(|| anyhow!("Response plist is not a dictionary"))?;

    let buffer = dict
        .get("sign-sap-setup-buffer")
        .ok_or_else(|| anyhow!("Response missing sign-sap-setup-buffer key"))?;

    let data = buffer
        .as_data()
        .ok_or_else(|| anyhow!("sign-sap-setup-buffer is not data type"))?;

    Ok(data.to_vec())
}

/// Fetch SAP setup certificate from Apple
pub fn fetch_sap_setup_cert() -> Result<Vec<u8>> {
    let url = "https://s.mzstatic.com/sap/setup.crt";
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .connect_timeout(std::time::Duration::from_secs(30))
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .context("Failed to build HTTP client")?;
    let resp = client
        .get(url)
        .send()
        .with_context(|| format!("Failed to fetch {}", url))?;
    if !resp.status().is_success() {
        bail!("Certificate fetch failed: HTTP {}", resp.status());
    }
    let bytes = resp.bytes().context("Failed to read certificate body")?;
    Ok(bytes.to_vec())
}

/// POST SAP setup exchange data to Apple server, return server response
pub fn post_sap_setup(client_data: &[u8]) -> Result<Vec<u8>> {
    let url = "https://play.itunes.apple.com/WebObjects/MZPlay.woa/wa/signSapSetup";
    let plist_body = encode_sap_setup_request_body(client_data)?;

    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .connect_timeout(std::time::Duration::from_secs(30))
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .context("Failed to build HTTP client")?;
    let resp = client
        .post(url)
        .header("Content-Type", "application/x-plist")
        .body(plist_body)
        .send()
        .with_context(|| format!("Failed to POST to {}", url))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        bail!(
            "SAP setup POST failed: HTTP {} — {}",
            status,
            if body.len() <= 500 {
                &body
            } else {
                &body[..body.floor_char_boundary(500)]
            }
        );
    }

    let resp_bytes = resp.bytes().context("Failed to read SAP setup response")?;
    parse_sap_setup_response_body(&resp_bytes)
}

// ── SapSession: high-level SAP session management ──

/// RAII guard that teardowns a SAP context on drop unless defused.
struct CtxGuard {
    teardown_addr: usize,
    ctx: u64,
    active: bool,
}

impl CtxGuard {
    fn new(teardown_addr: usize, ctx: u64) -> Self {
        Self {
            teardown_addr,
            ctx,
            active: true,
        }
    }
    /// Prevent teardown (call on success path).
    fn defuse(&mut self) -> u64 {
        self.active = false;
        self.ctx
    }
}

impl Drop for CtxGuard {
    fn drop(&mut self) {
        if self.active && self.ctx != 0 {
            eprintln!("[sap] CtxGuard: teardown leaked ctx={:#x}", self.ctx);
            unsafe { call_sap_teardown_cpp(self.teardown_addr, self.ctx) };
        }
    }
}

pub struct SapSession {
    _ssc: StoreServicesCore,
    ctx: u64,
    hwinfo: [u8; 24],
    sap_init_addr: usize,
    sap_exchange_addr: usize,
    sap_sign_addr: usize,
    sap_teardown_addr: usize,
    established_at: std::time::Instant,
    _so_path: PathBuf,
    _lib_dir: PathBuf,
}

impl SapSession {
    /// Full establish: load .so → bootstrap → Init → Exchange R1 → POST → Exchange R2
    pub fn establish(so_path: &Path, lib_dir: &Path) -> Result<Self> {
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        bail!("SAP session only supports aarch64/x86_64 hosts");

        // Phase A: Load libraries and bootstrap
        eprintln!("[sap] Loading {}...", so_path.display());
        let ssc = StoreServicesCore::load(so_path, lib_dir)?;

        let rc = ssc.bootstrap(lib_dir)?;
        eprintln!("[sap] bootstrap => {}", rc);

        install_wx_signal_handler();

        // Phase B: Resolve SAP symbols
        let sap_init_addr = ssc
            .get_symbol(SYM_SAP_INIT)
            .ok_or_else(|| anyhow!("Symbol not found: {} (FairPlaySAPInit)", SYM_SAP_INIT))?;
        let sap_exchange_addr = ssc.get_symbol(SYM_SAP_EXCHANGE).ok_or_else(|| {
            anyhow!(
                "Symbol not found: {} (FairPlaySAPExchange)",
                SYM_SAP_EXCHANGE
            )
        })?;
        let sap_sign_addr = ssc
            .get_symbol(SYM_FC3)
            .ok_or_else(|| anyhow!("Symbol not found: {} (FairPlaySAPSign)", SYM_FC3))?;
        let sap_teardown_addr = ssc.get_symbol(SYM_SAP_TEARDOWN).ok_or_else(|| {
            anyhow!(
                "Symbol not found: {} (FairPlaySAPTeardown)",
                SYM_SAP_TEARDOWN
            )
        })?;

        eprintln!(
            "[sap] Symbols resolved: Init={:#x} Exchange={:#x} Sign={:#x} Teardown={:#x}",
            sap_init_addr, sap_exchange_addr, sap_sign_addr, sap_teardown_addr
        );

        // Phase C: Construct FairPlayHwInfo
        let hw_id = get_hardware_id();
        let hwinfo = build_hwinfo_from_id(&hw_id);
        let id_len = hw_id.len().min(20) as u32;
        eprintln!(
            "[sap] FairPlayHwInfo: id_len={}, id={:02x?}",
            id_len,
            &hwinfo[4..4 + id_len as usize]
        );

        // Phase D: FairPlaySAPInit
        let mut ctx: u64 = 0;
        let init_rc =
            unsafe { call_sap_init_cpp(sap_init_addr, &mut ctx as *mut u64, hwinfo.as_ptr()) };
        eprintln!("[sap] FairPlaySAPInit => rc={}, ctx={:#x}", init_rc, ctx);
        if init_rc != 0 {
            bail!("FairPlaySAPInit failed with rc={}", init_rc);
        }
        if ctx == 0 {
            bail!("FairPlaySAPInit returned null context");
        }

        // Guard: auto-teardown ctx if any subsequent step fails
        let mut ctx_guard = CtxGuard::new(sap_teardown_addr, ctx);

        // Phase E: Fetch SAP setup certificate
        eprintln!("[sap] Fetching setup certificate...");
        let cert_bytes = fetch_sap_setup_cert()?;
        eprintln!("[sap] Certificate fetched: {} bytes", cert_bytes.len());

        // Phase F: FairPlaySAPExchange round 1
        let version = DEFAULT_SAP_VERSION;
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: u64 = 0;
        let mut rc1: i32 = 0;

        let exchange1_ret = unsafe {
            call_sap_exchange_cpp(
                sap_exchange_addr,
                version,
                hwinfo.as_ptr(),
                ctx,
                cert_bytes.as_ptr(),
                cert_bytes.len() as u32,
                &mut out_ptr,
                &mut out_len,
                &mut rc1,
            )
        };
        eprintln!(
            "[sap] FairPlaySAPExchange round 1 => ret={}, rc={}, out_len={}",
            exchange1_ret, rc1, out_len
        );
        if exchange1_ret != 0 {
            bail!(
                "FairPlaySAPExchange round 1 failed: ret={}, rc={}",
                exchange1_ret,
                rc1
            );
        }
        if rc1 != 1 {
            bail!("FairPlaySAPExchange round 1: expected rc=1, got rc={}", rc1);
        }

        let client_data = if !out_ptr.is_null() && out_len > 0 {
            let data = unsafe { std::slice::from_raw_parts(out_ptr, out_len as usize) }.to_vec();
            unsafe { libc::free(out_ptr as *mut libc::c_void) };
            data
        } else {
            bail!("FairPlaySAPExchange round 1 returned empty output");
        };
        eprintln!("[sap] Exchange round 1 output: {} bytes", client_data.len());

        // Phase G: POST exchange data to Apple server
        eprintln!("[sap] Posting SAP setup to Apple server...");
        let server_data = post_sap_setup(&client_data)?;
        eprintln!("[sap] Server response: {} bytes", server_data.len());

        // Phase H: FairPlaySAPExchange round 2
        let mut out_ptr2: *mut u8 = std::ptr::null_mut();
        let mut out_len2: u64 = 0;
        let mut rc2: i32 = 0;

        let exchange2_ret = unsafe {
            call_sap_exchange_cpp(
                sap_exchange_addr,
                version,
                hwinfo.as_ptr(),
                ctx,
                server_data.as_ptr(),
                server_data.len() as u32,
                &mut out_ptr2,
                &mut out_len2,
                &mut rc2,
            )
        };
        eprintln!(
            "[sap] FairPlaySAPExchange round 2 => ret={}, rc={}",
            exchange2_ret, rc2
        );
        if exchange2_ret != 0 {
            bail!(
                "FairPlaySAPExchange round 2 failed: ret={}, rc={}",
                exchange2_ret,
                rc2
            );
        }
        if rc2 != 0 {
            bail!("FairPlaySAPExchange round 2: expected rc=0, got rc={}", rc2);
        }
        // Free round 2 output buffer if allocated
        if !out_ptr2.is_null() {
            unsafe { libc::free(out_ptr2 as *mut libc::c_void) };
        }
        eprintln!("[sap] SAP session established successfully!");

        // Success — defuse the guard so ctx is not torn down
        let ctx = ctx_guard.defuse();

        Ok(Self {
            _ssc: ssc,
            ctx,
            hwinfo,
            sap_init_addr,
            sap_exchange_addr,
            sap_sign_addr,
            sap_teardown_addr,
            established_at: std::time::Instant::now(),
            _so_path: so_path.to_path_buf(),
            _lib_dir: lib_dir.to_path_buf(),
        })
    }

    /// Sign data using the established SAP session (can be called multiple times)
    pub fn sign(&self, input: &[u8]) -> Result<Vec<u8>> {
        let mut sign_out_ptr: *mut u8 = std::ptr::null_mut();
        let mut sign_out_len: u64 = 0;

        let sign_ret = unsafe {
            call_sap_sign_cpp(
                self.sap_sign_addr,
                self.ctx,
                input.as_ptr(),
                input.len() as u64,
                &mut sign_out_ptr,
                &mut sign_out_len,
            )
        };

        if sign_ret != 0 {
            bail!("FairPlaySAPSign failed with ret={}", sign_ret);
        }

        if sign_out_ptr.is_null() || sign_out_len == 0 {
            bail!("FairPlaySAPSign returned empty output");
        }

        let signature =
            unsafe { std::slice::from_raw_parts(sign_out_ptr, sign_out_len as usize) }.to_vec();

        // Free the buffer allocated by native code
        unsafe { libc::free(sign_out_ptr as *mut libc::c_void) };

        Ok(signature)
    }

    /// How long this session has been alive
    pub fn age(&self) -> std::time::Duration {
        self.established_at.elapsed()
    }

    /// Refresh SAP session: establish new context first, teardown old only on success.
    /// If the new handshake fails, the old session remains usable.
    pub fn refresh(&mut self) -> Result<()> {
        eprintln!(
            "[sap] Refreshing session (age: {:.1}s)...",
            self.age().as_secs_f64()
        );
        let old_ctx = self.ctx;

        // Init new context (keep old alive as fallback)
        let mut new_ctx: u64 = 0;
        let init_rc = unsafe {
            call_sap_init_cpp(
                self.sap_init_addr,
                &mut new_ctx as *mut u64,
                self.hwinfo.as_ptr(),
            )
        };
        eprintln!(
            "[sap] FairPlaySAPInit => rc={}, ctx={:#x}",
            init_rc, new_ctx
        );
        if init_rc != 0 {
            bail!(
                "FairPlaySAPInit failed on refresh: rc={} (old session preserved)",
                init_rc
            );
        }
        if new_ctx == 0 {
            bail!("FairPlaySAPInit returned null context on refresh (old session preserved)");
        }

        // Exchange round 1 with new context
        let cert_bytes = match fetch_sap_setup_cert() {
            Ok(c) => c,
            Err(e) => {
                // Cleanup new ctx, keep old
                unsafe { call_sap_teardown_cpp(self.sap_teardown_addr, new_ctx) };
                bail!("Certificate fetch failed on refresh (old session preserved): {e}");
            }
        };
        let version = DEFAULT_SAP_VERSION;
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: u64 = 0;
        let mut rc1: i32 = 0;

        let ex1_ret = unsafe {
            call_sap_exchange_cpp(
                self.sap_exchange_addr,
                version,
                self.hwinfo.as_ptr(),
                new_ctx,
                cert_bytes.as_ptr(),
                cert_bytes.len() as u32,
                &mut out_ptr,
                &mut out_len,
                &mut rc1,
            )
        };
        eprintln!(
            "[sap] Exchange round 1 => ret={}, rc={}, out_len={}",
            ex1_ret, rc1, out_len
        );
        if ex1_ret != 0 || rc1 != 1 {
            unsafe { call_sap_teardown_cpp(self.sap_teardown_addr, new_ctx) };
            bail!(
                "Exchange round 1 failed on refresh (old session preserved): ret={}, rc={}",
                ex1_ret,
                rc1
            );
        }

        let client_data = if !out_ptr.is_null() && out_len > 0 {
            let data = unsafe { std::slice::from_raw_parts(out_ptr, out_len as usize) }.to_vec();
            unsafe { libc::free(out_ptr as *mut libc::c_void) };
            data
        } else {
            unsafe { call_sap_teardown_cpp(self.sap_teardown_addr, new_ctx) };
            bail!("Exchange round 1 returned empty output on refresh (old session preserved)");
        };

        // POST to Apple server
        let server_data = match post_sap_setup(&client_data) {
            Ok(d) => d,
            Err(e) => {
                unsafe { call_sap_teardown_cpp(self.sap_teardown_addr, new_ctx) };
                bail!("SAP POST failed on refresh (old session preserved): {e}");
            }
        };

        // Exchange round 2
        let mut out_ptr2: *mut u8 = std::ptr::null_mut();
        let mut out_len2: u64 = 0;
        let mut rc2: i32 = 0;

        let ex2_ret = unsafe {
            call_sap_exchange_cpp(
                self.sap_exchange_addr,
                version,
                self.hwinfo.as_ptr(),
                new_ctx,
                server_data.as_ptr(),
                server_data.len() as u32,
                &mut out_ptr2,
                &mut out_len2,
                &mut rc2,
            )
        };
        eprintln!("[sap] Exchange round 2 => ret={}, rc={}", ex2_ret, rc2);
        if ex2_ret != 0 || rc2 != 0 {
            unsafe { call_sap_teardown_cpp(self.sap_teardown_addr, new_ctx) };
            bail!(
                "Exchange round 2 failed on refresh (old session preserved): ret={}, rc={}",
                ex2_ret,
                rc2
            );
        }
        if !out_ptr2.is_null() {
            unsafe { libc::free(out_ptr2 as *mut libc::c_void) };
        }

        // New session fully established — now teardown old
        if old_ctx != 0 {
            let td_ret = unsafe { call_sap_teardown_cpp(self.sap_teardown_addr, old_ctx) };
            eprintln!("[sap] Old session teardown => ret={}", td_ret);
        }
        self.ctx = new_ctx;
        self.established_at = std::time::Instant::now();
        eprintln!("[sap] Session refreshed successfully");
        Ok(())
    }
}

impl Drop for SapSession {
    fn drop(&mut self) {
        if self.ctx != 0 {
            let ret = unsafe { call_sap_teardown_cpp(self.sap_teardown_addr, self.ctx) };
            eprintln!("[sap] FairPlaySAPTeardown (drop) => ret={}", ret);
        }
    }
}
