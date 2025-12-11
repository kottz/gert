use std::path::Path;

use anyhow::{anyhow, Result};
use directories::ProjectDirs;

pub struct Config {
    pub client_id: String,
}

impl Config {
    pub fn load() -> Result<Self> {
        let client_id = load_client_id()?;
        Ok(Self { client_id })
    }
}

fn load_client_id() -> Result<String> {
    // First, check environment variable
    if let Ok(id) = std::env::var("GERT_CLIENT_ID") {
        let id = id.trim();
        if !id.is_empty() {
            println!("Using client id from GERT_CLIENT_ID env var");
            return Ok(id.to_string());
        }
    }

    // Then check config files
    if let Some(proj_dirs) = project_dirs() {
        let config_dir = proj_dirs.config_dir();

        for filename in [".env", "gert.conf"] {
            if let Some(id) = read_client_id_from_file(config_dir.join(filename)) {
                return Ok(id);
            }
        }
    }

    Err(anyhow!(
        "Missing client id. Set GERT_CLIENT_ID or add client_id=... to gert.conf in {}",
        config_path_hint()
    ))
}

fn read_client_id_from_file(path: impl AsRef<Path>) -> Option<String> {
    let contents = std::fs::read_to_string(path).ok()?;

    for line in contents.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim();

            if (key.eq_ignore_ascii_case("client_id") || key == "GERT_CLIENT_ID")
                && !value.is_empty()
            {
                return Some(value.to_string());
            }
        }
    }

    None
}

pub fn project_dirs() -> Option<ProjectDirs> {
    ProjectDirs::from("", "", "gert")
}

fn config_path_hint() -> String {
    project_dirs()
        .map(|p| p.config_dir().display().to_string())
        .unwrap_or_else(|| "configuration directory".to_string())
}
