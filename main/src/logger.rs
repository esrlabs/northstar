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
static TAG_SIZE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(20);

/// Initialize the logger
#[cfg(not(target_os = "android"))]
pub fn init() {
    use env_logger::fmt::Color;
    use std::{io::Write, sync::atomic::Ordering};

    let mut builder = env_logger::Builder::new();
    builder.parse_filters("northstar=debug");

    builder.format(|buf, record| {
        let mut style = buf.style();

        let timestamp = buf.timestamp_millis();
        let level = buf.default_styled_level(record.metadata().level());

        if let Some(module_path) = record
            .module_path()
            .and_then(|module_path| module_path.find(&"::").map(|p| &module_path[p + 2..]))
        {
            TAG_SIZE.fetch_max(module_path.len(), Ordering::SeqCst);
            let tag_size = TAG_SIZE.load(Ordering::SeqCst);
            fn hashed_color(i: &str) -> Color {
                // Some colors are hard to read on (at least) dark terminals
                // and I consider some others as ugly ;-)
                Color::Ansi256(match i.bytes().fold(42u8, |c, x| c ^ x) {
                    c @ 0..=1 => c + 2,
                    c @ 16..=21 => c + 6,
                    c @ 52..=55 | c @ 126..=129 => c + 4,
                    c @ 163..=165 | c @ 200..=201 => c + 3,
                    c @ 207 => c + 1,
                    c @ 232..=240 => c + 9,
                    c => c,
                })
            }
            style.set_color(hashed_color(module_path));

            writeln!(
                buf,
                "{}: {:>s$} {:<5}: {}",
                timestamp,
                style.value(module_path),
                level,
                record.args(),
                s = tag_size
            )
        } else {
            writeln!(
                buf,
                "{}: {} {:<5}: {}",
                timestamp,
                " ".repeat(TAG_SIZE.load(Ordering::SeqCst)),
                level,
                record.args(),
            )
        }
    });

    builder.init()
}
