use crate::backend::{BackendError, BackendResult};
use directories::ProjectDirs;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const QUALIFIER: &str = "zone";
const ORGANIZATION: &str = "dadoum";
const APPLICATION: &str = "SuperSideloader";

pub(crate) fn app_data_dir() -> Option<PathBuf> {
    project_dirs().map(|dirs| dirs.data_dir().to_path_buf())
}

pub(crate) fn open_app_data_folder() -> BackendResult<()> {
    let data_dir = app_data_dir().ok_or_else(|| {
        BackendError::Unsupported("The application data folder is not available.".to_string())
    })?;
    fs::create_dir_all(&data_dir).map_err(|source| BackendError::Io {
        action: "Create application data folder",
        path: data_dir.clone(),
        source,
    })?;

    let mut command = if cfg!(target_os = "macos") {
        Command::new("open")
    } else if cfg!(target_os = "windows") {
        Command::new("explorer")
    } else {
        Command::new("xdg-open")
    };

    command
        .arg(&data_dir)
        .spawn()
        .map_err(|source| BackendError::Command {
            action: "Open application data folder",
            source,
        })?;
    Ok(())
}

pub(crate) fn save_provisioning_profile(
    folder: PathBuf,
    profile_name: &str,
    bytes: Vec<u8>,
) -> BackendResult<PathBuf> {
    let destination = folder.join(mobileprovision_file_name(profile_name));
    fs::write(&destination, bytes).map_err(|source| BackendError::Io {
        action: "Save provisioning profile",
        path: destination.clone(),
        source,
    })?;
    Ok(destination)
}

fn project_dirs() -> Option<ProjectDirs> {
    ProjectDirs::from(QUALIFIER, ORGANIZATION, APPLICATION)
}

fn mobileprovision_file_name(profile_name: &str) -> String {
    let mut name = profile_name
        .chars()
        .map(|character| match character {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            character if character.is_control() => '_',
            character => character,
        })
        .collect::<String>();
    name = name.trim().trim_matches('.').to_string();
    if name.is_empty() {
        name.push_str("provisioning-profile");
    }
    if !name.ends_with(".mobileprovision") {
        name.push_str(".mobileprovision");
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisioning_profile_file_names_are_sanitized() {
        assert_eq!(
            mobileprovision_file_name("Team/Profile:Dev"),
            "Team_Profile_Dev.mobileprovision"
        );
        assert_eq!(
            mobileprovision_file_name("already.mobileprovision"),
            "already.mobileprovision"
        );
        assert_eq!(
            mobileprovision_file_name("..."),
            "provisioning-profile.mobileprovision"
        );
    }
}
