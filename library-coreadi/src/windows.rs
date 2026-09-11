// TODO move this to another crate

use adi::core_adi::{CoreADIADIProxy, CoreADIParameters, CoreADIProxy};
use md5::{Digest, Md5};
use std::ffi::{CStr, OsStr};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    ERROR_BUFFER_OVERFLOW, ERROR_MORE_DATA, FreeLibrary, HMODULE,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_INCLUDE_ALL_INTERFACES, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationW;
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
    LoadLibraryExW,
};
use windows_sys::Win32::System::Registry::*;
use windows_sys::Win32::System::WindowsProgramming::{
    GetComputerNameW, GetCurrentHwProfileW, HW_PROFILE_INFOW,
};

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

fn open_key(root: HKEY, path: &CStr, view: u32) -> Option<Key> {
    let mut key = null_mut();
    (unsafe { RegOpenKeyExA(root, path.as_ptr().cast(), 0, KEY_READ | view, &mut key) } == 0)
        .then_some(Key(key))
}

fn value_bytes(key: HKEY, name: &CStr) -> Option<Vec<u8>> {
    let mut size = 0;
    if unsafe {
        RegQueryValueExA(
            key,
            name.as_ptr().cast(),
            null(),
            null_mut(),
            null_mut(),
            &mut size,
        )
    } != 0
    {
        return None;
    }
    loop {
        let mut bytes = vec![0; size as usize];
        let result = unsafe {
            RegQueryValueExA(
                key,
                name.as_ptr().cast(),
                null(),
                null_mut(),
                bytes.as_mut_ptr(),
                &mut size,
            )
        };
        if result == ERROR_MORE_DATA {
            continue;
        }
        if result != 0 {
            return None;
        }
        bytes.truncate(size as usize);
        return Some(bytes);
    }
}

fn registry_bytes(path: &CStr, name: &CStr) -> Option<Vec<u8>> {
    let key = open_key(HKEY_LOCAL_MACHINE, path, 0)?;
    value_bytes(key.0, name)
}

fn registry_path(key: HKEY, name: &CStr) -> Option<PathBuf> {
    // Paths must use the Unicode API; identity values deliberately use ANSI.
    let name: Vec<u16> = name
        .to_bytes()
        .iter()
        .map(|b| *b as u16)
        .chain(Some(0))
        .collect();
    let mut size = 0;
    if unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            null(),
            null_mut(),
            null_mut(),
            &mut size,
        )
    } != 0
    {
        return None;
    }
    let mut data = vec![0u16; size as usize / 2 + 1];
    if unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            null(),
            null_mut(),
            data.as_mut_ptr().cast(),
            &mut size,
        )
    } != 0
    {
        return None;
    }
    let len = data.iter().position(|c| *c == 0).unwrap_or(data.len());
    use std::os::windows::ffi::OsStringExt;
    Some(std::ffi::OsString::from_wide(&data[..len]).into())
}

fn first_mac() -> Option<Vec<u8>> {
    let mut size = 0;
    // iTunes takes the first adapter, including interfaces which are down.
    // u64 storage guarantees the alignment required by IP_ADAPTER_ADDRESSES.
    loop {
        let mut storage = vec![0u64; (size as usize).div_ceil(8).max(1)];
        let adapter = storage.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let result = unsafe {
            GetAdaptersAddresses(
                0,
                GAA_FLAG_INCLUDE_ALL_INTERFACES,
                null(),
                adapter,
                &mut size,
            )
        };
        if result == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if result != 0 {
            return None;
        }
        let adapter = unsafe { &*adapter };
        let mut mac = vec![0; 6];
        let length = (adapter.PhysicalAddressLength as usize).min(6);
        mac[..length].copy_from_slice(&adapter.PhysicalAddress[..length]);
        return Some(mac);
    }
}

fn volume_serial() -> Option<Vec<u8>> {
    let mut serial = 0u32;
    let root = wide(OsStr::new("C:\\"));
    (unsafe {
        GetVolumeInformationW(
            root.as_ptr(),
            null_mut(),
            0,
            &mut serial,
            null_mut(),
            null_mut(),
            null_mut(),
            0,
        )
    } != 0)
        .then(|| serial.to_le_bytes().to_vec())
}

fn computer_name_bytes() -> Option<Vec<u8>> {
    let mut name = [0u16; 16];
    let mut length = name.len() as u32;
    if unsafe { GetComputerNameW(name.as_mut_ptr(), &mut length) } == 0 {
        return None;
    }
    // Compatibility quirk: iTunes passes the WCHAR count as a BYTE count.
    let mut bytes: Vec<_> = name.iter().flat_map(|c| c.to_le_bytes()).collect();
    bytes.truncate(length as usize);
    Some(bytes)
}

fn hardware_profile_bytes() -> Option<Vec<u8>> {
    let mut profile: HW_PROFILE_INFOW = unsafe { std::mem::zeroed() };
    if unsafe { GetCurrentHwProfileW(&mut profile) } == 0 {
        return None;
    }
    Some(
        profile
            .szHwProfileGuid
            .iter()
            .take_while(|c| **c != 0)
            .flat_map(|c| c.to_le_bytes())
            .collect(),
    )
}

fn format_identifier(parts: &[Option<Vec<u8>>; 7]) -> String {
    parts
        .iter()
        .map(|part| match part {
            Some(bytes) => Md5::digest(bytes)[..4]
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect(),
            None => "00000000".to_string(),
        })
        .collect::<Vec<String>>()
        .join(".")
}

/// Compute the same device identifier used by iTunes on Windows 8+.
/// Unavailable hardware components have zero segments, as in iTunes.
pub fn device_identifier() -> String {
    format_identifier(&[
        first_mac(),
        volume_serial(),
        registry_bytes(
            c"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            c"ProductId",
        ),
        registry_bytes(
            c"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
            c"ProcessorNameString",
        ),
        registry_bytes(c"HARDWARE\\DESCRIPTION\\System", c"SystemBiosVersion"),
        computer_name_bytes(),
        hardware_profile_bytes(),
    ])
}

fn add_directory(candidates: &mut Vec<PathBuf>, directory: &Path) {
    let names: &[&str] = if cfg!(target_arch = "x86_64") {
        &["CoreADI64.dll", "CoreADI.dll"]
    } else {
        &["CoreADI.dll"]
    };
    for name in names {
        let path = directory.join(name);
        if !candidates.contains(&path) {
            candidates.push(path);
        }
    }
}

/// Candidate paths from registered desktop/Store installations and standard folders.
pub fn library_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    for root in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
        for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
            if let Some(key) = open_key(
                root,
                c"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\iTunes.exe",
                view,
            ) {
                if let Some(path) = registry_path(key.0, c"") {
                    if let Some(parent) = path.parent() {
                        add_directory(&mut candidates, parent);
                    }
                }
            }
        }
    }
    for variable in ["ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"] {
        if let Some(root) = std::env::var_os(variable) {
            let root = PathBuf::from(root);
            for suffix in [
                "iTunes",
                "Common Files/Apple/Apple Application Support",
                "Common Files/Apple/Internet Services",
                "Apple/Apple Application Support",
            ] {
                add_directory(&mut candidates, &root.join(suffix));
            }
        }
    }
    for variable in [
        "CommonProgramW6432",
        "CommonProgramFiles",
        "CommonProgramFiles(x86)",
    ] {
        if let Some(root) = std::env::var_os(variable) {
            for suffix in ["Apple/Apple Application Support", "Apple/Internet Services"] {
                add_directory(&mut candidates, &PathBuf::from(&root).join(suffix));
            }
        }
    }
    if let Some(key) = open_key(HKEY_CURRENT_USER, c"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository\\Packages", KEY_WOW64_64KEY) {
        for index in 0.. {
            let mut name = vec![0u8; 512];
            let mut len = name.len() as u32;
            if unsafe { RegEnumKeyExA(key.0, index, name.as_mut_ptr(), &mut len, null(), null_mut(), null_mut(), null_mut()) } != 0 { break; }
            name.truncate(len as usize);
            if ![b"AppleInc.iTunes_".as_slice(), b"AppleInc.iCloud_".as_slice()].iter().any(|prefix| name.starts_with(prefix)) { continue; }
            name.push(0);
            if let Some(package) = open_key(key.0, CStr::from_bytes_with_nul(&name).unwrap(), 0) {
                if let Some(root) = registry_path(package.0, c"PackageRootFolder") {
                    for suffix in ["", "VFS/ProgramFilesX64/iTunes", "VFS/ProgramFilesCommonX64/Apple/Internet Services", "VFS/ProgramFilesCommonX64/Apple/Apple Application Support"] {
                        add_directory(&mut candidates, &root.join(suffix));
                    }
                }
            }
        }
    }
    candidates
}

fn compatible_library(path: &Path) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut dos = [0; 64];
    if file.read_exact(&mut dos).is_err() || &dos[..2] != b"MZ" {
        return false;
    }
    let offset = u32::from_le_bytes(dos[60..64].try_into().unwrap());
    if file.seek(SeekFrom::Start(offset as u64)).is_err() {
        return false;
    }
    let mut pe = [0; 6];
    file.read_exact(&mut pe).is_ok()
        && &pe[..4] == b"PE\0\0"
        && u16::from_le_bytes([pe[4], pe[5]])
            == if cfg!(target_arch = "x86_64") {
                0x8664
            } else if cfg!(target_arch = "aarch64") {
                0xaa64
            } else {
                0x14c
            }
}

pub fn find_library() -> Option<PathBuf> {
    library_candidates()
        .into_iter()
        .find(|path| compatible_library(path))
}

/// Owns the DLL and uses its directory for dependency resolution, without changing PATH.
pub struct WindowsCoreADIProxy {
    module: HMODULE,
    dispatcher: unsafe extern "C" fn(u32, *const CoreADIParameters) -> i32,
}

impl WindowsCoreADIProxy {
    pub fn open(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let path = std::fs::canonicalize(path)?;
        let module = unsafe {
            LoadLibraryExW(
                wide(path.as_os_str()).as_ptr(),
                null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
            )
        };
        if module.is_null() {
            return Err(io::Error::last_os_error().into());
        }
        let symbol = unsafe { GetProcAddress(module, c"vdfut768ig".as_ptr().cast()) };
        let Some(symbol) = symbol else {
            let error = io::Error::last_os_error();
            unsafe {
                FreeLibrary(module);
            }
            return Err(error.into());
        };
        let proxy = Self {
            module,
            dispatcher: unsafe { std::mem::transmute(symbol) },
        };
        proxy.initialize()?;
        Ok(proxy)
    }
}

impl CoreADIProxy for WindowsCoreADIProxy {
    unsafe fn dispatch(&self, code: u32, parameters: *const CoreADIParameters) -> i32 {
        unsafe { (self.dispatcher)(code, parameters) }
    }
}

impl Drop for WindowsCoreADIProxy {
    fn drop(&mut self) {
        let _ = self.finalize();
        unsafe {
            FreeLibrary(self.module);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discovery_rejects_wrong_architecture_and_malformed_files() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("CoreADI.dll");
        assert!(!compatible_library(&path));
        std::fs::write(&path, b"not a DLL").unwrap();
        assert!(!compatible_library(&path));
        let mut bytes = vec![0u8; 70];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[60..64].copy_from_slice(&64u32.to_le_bytes());
        bytes[64..68].copy_from_slice(b"PE\0\0");
        let native: u16 = if cfg!(target_arch = "x86_64") {
            0x8664
        } else if cfg!(target_arch = "aarch64") {
            0xaa64
        } else {
            0x14c
        };
        bytes[68..70].copy_from_slice(&native.to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();
        assert!(compatible_library(&path));
        bytes[68..70].copy_from_slice(&0xffffu16.to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();
        assert!(!compatible_library(&path));
    }

    #[test]
    fn identifier_preserves_order_null_bytes_and_missing_components() {
        assert_eq!(
            format_identifier(&[
                Some(b"abc".to_vec()),
                None,
                Some(vec![]),
                Some(b"abc\0".to_vec()),
                None,
                None,
                None
            ]),
            "90015098.00000000.D41D8CD9.147A664A.00000000.00000000.00000000"
        );
    }
}
