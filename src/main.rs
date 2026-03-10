mod config;
mod display;
mod oauth;
mod storage;
mod twitch;

use anyhow::{Context, Result};

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let config = config::Config::load()?;

    // Try to use cached results first
    if let Some(cached) = try_use_cache() {
        println!("Using cached live channel results (polled < 60s ago).");
        display::show_channels(&cached.channels);
        return Ok(());
    }

    // Fetch fresh data
    let mut api = twitch::Api::new(&config)?;
    let user_id = get_or_fetch_user_id(&mut api)?;
    let channels = fetch_channels_with_retry(&mut api, &user_id)?;

    storage::save_cache(&user_id, &channels)?;
    display::show_channels(&channels);

    Ok(())
}

fn try_use_cache() -> Option<storage::CachePayload> {
    let stored_user_id = storage::load_user_id();
    let payload = storage::load_cache()?;

    // Reject cache if user_id changed
    let user_mismatch = stored_user_id
        .as_ref()
        .zip(payload.user_id.as_ref())
        .is_some_and(|(stored, cached)| stored != cached);

    if user_mismatch {
        return None;
    }

    // Persist user_id from cache if we didn't have one stored
    if stored_user_id.is_none() {
        if let Some(ref id) = payload.user_id {
            let _ = storage::save_user_id(id);
        }
    }

    Some(payload)
}

fn get_or_fetch_user_id(api: &mut twitch::Api) -> Result<String> {
    if let Some(id) = storage::load_user_id() {
        return Ok(id);
    }

    let user_id = match api.get_user_id() {
        Ok(id) => id,
        Err(err) if twitch::is_unauthorized(&err) => {
            println!("Access token expired. Re-authenticating...");
            api.refresh_auth()?;
            api.get_user_id()
                .context("failed to fetch user ID after re-authentication")?
        }
        Err(err) => return Err(err),
    };

    storage::save_user_id(&user_id)?;
    Ok(user_id)
}

fn fetch_channels_with_retry(
    api: &mut twitch::Api,
    user_id: &str,
) -> Result<Vec<twitch::LiveChannel>> {
    match api.get_live_followed_channels(user_id) {
        Ok(channels) => Ok(channels),
        Err(err) if twitch::is_unauthorized(&err) => {
            println!("Access token expired during execution. Re-authenticating...");
            api.refresh_auth()?;
            api.get_live_followed_channels(user_id)
                .context("failed to fetch channels after re-authentication")
        }
        Err(err) => Err(err),
    }
}
