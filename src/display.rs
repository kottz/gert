use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

use crate::twitch::LiveChannel;

pub fn show_channels(channels: &[LiveChannel]) {
    if channels.is_empty() {
        println!("No followed channels are live right now.");
        return;
    }

    println!("\nLIVE channels you follow:");

    for channel in channels {
        let game = channel.game_name.as_deref().unwrap_or("Unknown game");
        let uptime = format_uptime(channel.started_at.as_deref());

        println!(
            "{} — {} — {} — live for {} ({} viewers)",
            channel.user_name, channel.title, game, uptime, channel.viewer_count
        );
    }
}

fn format_uptime(started_at: Option<&str>) -> String {
    let Some(started_at) = started_at else {
        return "unknown".to_string();
    };

    let Ok(start) = OffsetDateTime::parse(started_at, &Rfc3339) else {
        return "unknown".to_string();
    };

    let elapsed = OffsetDateTime::now_utc() - start;

    if elapsed.is_negative() {
        return "just now".to_string();
    }

    format_duration(elapsed)
}

fn format_duration(duration: Duration) -> String {
    let secs = duration.whole_seconds();

    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let minutes = (secs % 3_600) / 60;
    let seconds = secs % 60;

    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}
