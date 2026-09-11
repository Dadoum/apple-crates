use crate::domain::MachineIdentity;
use std::env;

#[cfg(target_os = "windows")]
#[path = "windows_system.rs"]
mod windows_system;

pub(crate) fn machine_identity() -> MachineIdentity {
    platform_machine_identity().unwrap_or_else(fallback_machine_identity)
}

fn fallback_machine_identity() -> MachineIdentity {
    let machine_name = env::var("HOSTNAME")
        .or_else(|_| env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "Local Machine".to_string());
    let os_name = env::consts::OS.to_string();
    let os_version = env::var("OS_VERSION").unwrap_or_else(|_| "Unknown".to_string());
    let machine_id = env::var("MACHINE_ID")
        .unwrap_or_else(|_| "A8B31C86-359B-4D95-8950-BA5DD8FFC46F".to_string());

    MachineIdentity {
        machine_name,
        os_name,
        os_version,
        machine_id,
    }
}

#[cfg(target_os = "macos")]
fn platform_machine_identity() -> Option<MachineIdentity> {
    let machine_name = macos::hardware_model()?;
    let (os_name, os_version) = macos::operating_system()?;
    let machine_id = macos::platform_uuid()?;

    Some(MachineIdentity {
        machine_name,
        os_name,
        os_version,
        machine_id,
    })
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_machine_identity() -> MachineIdentity {
    MachineIdentity {
        machine_name: "PC".to_string(),
        os_name: "Windows".to_string(),
        os_version: windows_system::information().unwrap_or_else(|error| {
            log::warn!("Failed to read Windows system information: {error}");
            "Unknown".into()
        }),
        machine_id: library_coreadi::windows::device_identifier(),
    }
}

#[cfg(target_os = "windows")]
fn platform_machine_identity() -> Option<MachineIdentity> {
    Some(windows_machine_identity())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn platform_machine_identity() -> Option<MachineIdentity> {
    None
}

#[cfg(target_os = "macos")]
mod macos {
    use core_foundation::base::{kCFAllocatorDefault, CFAllocatorRef, CFTypeRef, TCFType};
    use core_foundation::dictionary::{CFDictionaryRef, CFMutableDictionaryRef};
    use core_foundation::string::{CFString, CFStringRef};
    use libc::{c_char, c_void, size_t};
    use plist::{Dictionary, Value};
    use std::ffi::CString;
    use std::ptr;

    type KernReturn = i32;
    type MachPort = u32;
    type IoObject = u32;
    type IoRegistryEntry = IoObject;
    type IoService = IoObject;

    const K_IO_MAIN_PORT_DEFAULT: MachPort = 0;
    const K_IO_PLATFORM_EXPERT_DEVICE: &[u8] = b"IOPlatformExpertDevice\0";
    const K_IO_PLATFORM_UUID: &str = "IOPlatformUUID";
    const SYSTEM_VERSION_PLIST: &str = "/System/Library/CoreServices/SystemVersion.plist";

    #[link(name = "IOKit", kind = "framework")]
    extern "C" {
        fn IOServiceMatching(name: *const c_char) -> CFMutableDictionaryRef;
        fn IOServiceGetMatchingService(main_port: MachPort, matching: CFDictionaryRef)
            -> IoService;
        fn IORegistryEntryCreateCFProperty(
            entry: IoRegistryEntry,
            key: CFStringRef,
            allocator: CFAllocatorRef,
            options: u32,
        ) -> CFTypeRef;
        fn IOObjectRelease(object: IoObject) -> KernReturn;
    }

    pub(super) fn hardware_model() -> Option<String> {
        sysctl_string("hw.model")
    }

    pub(super) fn operating_system() -> Option<(String, String)> {
        let plist = plist::from_file::<_, Dictionary>(SYSTEM_VERSION_PLIST).ok()?;
        let product_name = plist_string(&plist, "ProductName").unwrap_or("macOS");
        let product_version = plist_string(&plist, "ProductVersion")?;
        let build_version = plist_string(&plist, "ProductBuildVersion")?;

        Some((
            product_name.to_string(),
            format!("{product_version};{build_version}"),
        ))
    }

    pub(super) fn platform_uuid() -> Option<String> {
        let matching =
            unsafe { IOServiceMatching(K_IO_PLATFORM_EXPERT_DEVICE.as_ptr() as *const c_char) };
        if matching.is_null() {
            return None;
        }

        let service = unsafe {
            IOServiceGetMatchingService(K_IO_MAIN_PORT_DEFAULT, matching as CFDictionaryRef)
        };
        if service == 0 {
            return None;
        }

        let key = CFString::new(K_IO_PLATFORM_UUID);
        let value = unsafe {
            IORegistryEntryCreateCFProperty(
                service,
                key.as_concrete_TypeRef(),
                kCFAllocatorDefault,
                0,
            )
        };
        unsafe {
            IOObjectRelease(service);
        }

        if value.is_null() {
            return None;
        }

        let value = unsafe { CFString::wrap_under_create_rule(value as CFStringRef) };
        Some(value.to_string())
    }

    fn sysctl_string(name: &str) -> Option<String> {
        let name = CString::new(name).ok()?;
        let mut len: size_t = 0;
        let len_result = unsafe {
            libc::sysctlbyname(name.as_ptr(), ptr::null_mut(), &mut len, ptr::null_mut(), 0)
        };
        if len_result != 0 || len == 0 {
            return None;
        }

        let mut value = vec![0u8; len];
        let result = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                value.as_mut_ptr() as *mut c_void,
                &mut len,
                ptr::null_mut(),
                0,
            )
        };
        if result != 0 {
            return None;
        }

        if value.last() == Some(&0) {
            value.pop();
        }
        String::from_utf8(value).ok()
    }

    fn plist_string<'a>(plist: &'a Dictionary, key: &str) -> Option<&'a str> {
        plist.get(key).and_then(Value::as_string)
    }
}
