use crate::bundle_information::BundleInformation;

#[derive(Clone)]
pub struct Device {
    pub device_model: String,
    pub operating_system_information: String,
    pub device_uuid: String,
}

impl Device {
    pub fn server_friendly_description(
        &self,
        authentication_framework: &BundleInformation,
        application_information: &BundleInformation,
    ) -> String {
        format!(
            "<{}> <{}> <{}/{} ({}/{})>",
            self.device_model,
            self.operating_system_information,
            authentication_framework.bundle_name,
            authentication_framework.bundle_version,
            application_information.bundle_name,
            application_information.bundle_version,
        )
    }
}
