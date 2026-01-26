use crate::DeveloperAction;
use crate::DeveloperActionBase;
use crate::{impl_developer_action, impl_developer_action_base};
use plist::Dictionary;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct ViewDeveloperAction {}
impl_developer_action_base!(ViewDeveloperAction, "viewDeveloper.action");

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Developer {
    pub developer_id: String,
    pub person_id: u64,
    pub first_name: String,
    pub last_name: String,
    pub ds_first_name: String,
    pub ds_last_name: String,
    pub email: String,
    pub developer_status: String, // TODO: DeveloperStatus enum
}

#[derive(Debug, Deserialize)]
pub struct DeveloperView {
    pub teams: Vec<()>,
    pub developer: Developer,
}
impl_developer_action!(ViewDeveloperAction, DeveloperView);
