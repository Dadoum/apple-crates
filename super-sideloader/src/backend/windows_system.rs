use std::io;
use windows_sys::Win32::System::SystemInformation::*;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlGetVersion(version: *mut OSVERSIONINFOEXW) -> i32;
}

/// Read the real kernel version rather than the manifest-dependent GetVersionEx result.
pub(super) fn information() -> io::Result<String> {
    let mut version: OSVERSIONINFOEXW = unsafe { std::mem::zeroed() };
    version.dwOSVersionInfoSize = std::mem::size_of_val(&version) as u32;
    let status = unsafe { RtlGetVersion(&mut version) };
    if status < 0 {
        return Err(io::Error::other(format!(
            "RtlGetVersion failed: {status:#x}"
        )));
    }
    let mut product = 0;
    if unsafe {
        GetProductInfo(
            version.dwMajorVersion,
            version.dwMinorVersion,
            version.wServicePackMajor as u32,
            version.wServicePackMinor as u32,
            &mut product,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut system: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    unsafe {
        GetNativeSystemInfo(&mut system);
    }
    let architecture = unsafe { system.Anonymous.Anonymous.wProcessorArchitecture };
    Ok(format!(
        "{}.{}.{}/SP{}.{}.{}; {} {}; {}",
        version.dwMajorVersion,
        version.dwMinorVersion,
        version.dwBuildNumber,
        version.wServicePackMajor,
        version.wServicePackMinor,
        version.dwBuildNumber,
        release_name(&version),
        edition_name(product),
        architecture_name(architecture)
    ))
}

fn release_name(version: &OSVERSIONINFOEXW) -> String {
    // Server releases share kernel build numbers with client releases.
    if version.wProductType != 1 {
        return "Windows Server".into();
    }
    match (
        version.dwMajorVersion,
        version.dwMinorVersion,
        version.dwBuildNumber,
    ) {
        (10, 0, 22000..) => "Win11".into(),
        (10, 0, _) => "Win10".into(),
        (6, 3, _) => "Win8.1".into(),
        (6, 2, _) => "Win8".into(),
        (6, 1, _) => "Win7".into(),
        (major, minor, _) => format!("Win{major}.{minor}"),
    }
}

fn edition_name(product: u32) -> String {
    let name = match product {
        // These newer SKU values are documented by GetProductInfo but absent
        // from this windows-sys release.
        0xbc => "IoT Enterprise",
        0xbf => "IoT Enterprise LTSC",
        0xa4 => "Pro Education",
        0xa5 => "Pro Education N",
        PRODUCT_PROFESSIONAL => "Pro",
        PRODUCT_PROFESSIONAL_N => "Pro N",
        PRODUCT_PRO_WORKSTATION => "Pro for Workstations",
        PRODUCT_PRO_WORKSTATION_N => "Pro for Workstations N",
        PRODUCT_CORE => "Home",
        PRODUCT_CORE_N => "Home N",
        PRODUCT_CORE_SINGLELANGUAGE => "Home Single Language",
        PRODUCT_CORE_COUNTRYSPECIFIC => "Home China",
        PRODUCT_ENTERPRISE => "Enterprise",
        PRODUCT_ENTERPRISE_N => "Enterprise N",
        PRODUCT_ENTERPRISE_S => "Enterprise LTSC",
        PRODUCT_ENTERPRISE_S_N => "Enterprise LTSC N",
        PRODUCT_EDUCATION => "Education",
        PRODUCT_EDUCATION_N => "Education N",
        PRODUCT_STANDARD_SERVER => "Standard",
        PRODUCT_DATACENTER_SERVER => "Datacenter",
        // Preserve the actual SKU when it has no friendly label here.
        _ => return format!("SKU {product:#x}"),
    };
    name.into()
}

fn architecture_name(architecture: u16) -> &'static str {
    match architecture {
        PROCESSOR_ARCHITECTURE_AMD64 => "x64",
        PROCESSOR_ARCHITECTURE_INTEL => "x86",
        PROCESSOR_ARCHITECTURE_ARM64 => "ARM64",
        PROCESSOR_ARCHITECTURE_ARM => "ARM",
        PROCESSOR_ARCHITECTURE_IA64 => "IA64",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn windows_11_is_distinguished_from_windows_10_and_server() {
        let mut version: OSVERSIONINFOEXW = unsafe { std::mem::zeroed() };
        version.dwMajorVersion = 10;
        version.wProductType = 1;
        version.dwBuildNumber = 19045;
        assert_eq!(release_name(&version), "Win10");
        version.dwBuildNumber = 22000;
        assert_eq!(release_name(&version), "Win11");
        version.wProductType = 3;
        assert_eq!(release_name(&version), "Windows Server");
        assert_eq!(edition_name(0xbf), "IoT Enterprise LTSC");
        assert_eq!(edition_name(PRODUCT_CORE), "Home");
        assert_eq!(edition_name(PRODUCT_PROFESSIONAL), "Pro");
        assert_eq!(architecture_name(PROCESSOR_ARCHITECTURE_ARM64), "ARM64");
    }
}
