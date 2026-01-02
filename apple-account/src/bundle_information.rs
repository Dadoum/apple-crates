pub struct BundleInformation<'lt> { // Maybe simplify to 'static?
    pub bundle_name: &'lt str,
    pub bundle_identifier: &'lt str,
    pub bundle_version: &'lt str,
}

/// AuthKit from macOS 15.6.1
pub const AUTH_KIT_BUNDLE_INFORMATION: BundleInformation = BundleInformation {
    bundle_name: "AuthKit",
    bundle_identifier: "com.apple.AuthKit",
    bundle_version: "1",
};

/// Xcode 16.4
pub const XCODE_BUNDLE_INFORMATION: BundleInformation = BundleInformation {
    bundle_name: "Xcode",
    bundle_identifier: "com.apple.dt.Xcode",
    bundle_version: "23792",
};

/// Apple TV 1.5.6 (macOS Sequoia 15.7.3)
pub const APPLE_TV_BUNDLE_INFORMATION: BundleInformation = BundleInformation {
    bundle_name: "TV",
    bundle_identifier: "com.apple.TV",
    bundle_version: "1.5.6",
};
