/// Initialize the logger
#[cfg(target_os = "android")]
pub fn init() {
    android_logd_logger::builder()
        .tag("northstar")
        .prepend_module(false)
        .parse_filters("northstar=debug")
        .init();
}

#[cfg(not(target_os = "android"))]
static TAG_SIZE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(28);

/// Initialize the logger
#[cfg(not(target_os = "android"))]
pub fn init() {
    use env_logger::fmt::Color;
    use std::{io::Write, sync::atomic::Ordering};

    fn color(target: &str) -> Color {
        // Some colors are hard to read on (at least) dark terminals
        // and I consider some others as ugly ;-)
        let hash = target.bytes().fold(42u8, |c, x| c ^ x);
        Color::Ansi256(match hash {
            c @ 0..=1 => c + 2,
            c @ 16..=21 => c + 6,
            c @ 52..=55 | c @ 126..=129 => c + 4,
            c @ 163..=165 | c @ 200..=201 => c + 3,
            c @ 207 => c + 1,
            c @ 232..=240 => c + 9,
            c => c,
        })
    }

    let mut builder = env_logger::Builder::new();
    builder.parse_filters("northstar=debug");

    builder.format(|buf, record| {
        let timestamp = buf.timestamp_millis().to_string();
        let timestamp = timestamp.strip_suffix('Z').unwrap();

        let mut level = buf.default_level_style(record.metadata().level());
        level.set_bold(true);
        let level = level.value(record.metadata().level().as_str());

        let pid = std::process::id().to_string();
        let mut pid_style = buf.style();
        pid_style.set_color(color(&pid));

        if let Some(target) = Option::from(record.target().is_empty())
            .map(|_| record.target())
            .or_else(|| record.module_path())
            .and_then(|module_path| module_path.find(&"::").map(|p| &module_path[p + 2..]))
        {
            let mut tag_style = buf.style();
            TAG_SIZE.fetch_max(target.len(), Ordering::SeqCst);
            let tag_size = TAG_SIZE.load(Ordering::SeqCst);
            tag_style.set_color(color(target));

            writeln!(
                buf,
                "{} {:>s$} {}  {:<5}: {}",
                timestamp,
                tag_style.value(target),
                pid_style.value("⬤"),
                level,
                record.args(),
                s = tag_size,
            )
        } else {
            writeln!(
                buf,
                "{} {} {}  {:<5}: {}",
                timestamp,
                " ".repeat(TAG_SIZE.load(Ordering::SeqCst)),
                pid_style.value("⬤"),
                level,
                record.args(),
            )
        }
    });

    builder.init()
}
