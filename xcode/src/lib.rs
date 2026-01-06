use apple_account::bundle_information::BundleInformation;
use apple_account::grandslam::AppTokenIdentifier;

/// From Xcode 16.4
pub const XCODE_BUNDLE_INFORMATION: BundleInformation = BundleInformation {
    bundle_name: "Xcode",
    bundle_identifier: "com.apple.dt.Xcode",
    bundle_version: "23792",
};

pub const XCODE_TOKEN_IDENTIFIER: AppTokenIdentifier =
    AppTokenIdentifier("com.apple.gs.xcode.auth");
