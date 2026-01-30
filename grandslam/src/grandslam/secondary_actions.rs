pub enum SecondaryActionType {
    ServerDriven(String),
}

impl From<String> for SecondaryActionType {
    fn from(value: String) -> Self {
        match value {
            // "".to_string() => SecondaryActionType::ServerDriven("")
            server_drive_action => SecondaryActionType::ServerDriven(server_drive_action),
        }
    }
}
