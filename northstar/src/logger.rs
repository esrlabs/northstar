// Copyright (c) 2021 E.S.R.Labs. All rights reserved.
//
// NOTICE:  All information contained herein is, and remains
// the property of E.S.R.Labs and its suppliers, if any.
// The intellectual and technical concepts contained herein are
// proprietary to E.S.R.Labs and its suppliers and may be covered
// by German and Foreign Patents, patents in process, and are protected
// by trade secret or copyright law.
// Dissemination of this information or reproduction of this material
// is strictly forbidden unless prior written permission is obtained
// from E.S.R.Labs.

/// Initialize the logger
#[cfg(target_os = "android")]
pub fn init() {
    android_logd_logger::builder()
        .tag("northstar")
        .prepend_module(false)
        .parse_filters("northstar=debug")
        .init();
}

/// Initialize the logger
#[cfg(not(target_os = "android"))]
pub fn init() {
    use env_logger::fmt::Color;
    use std::io::Write;

    let mut builder = env_logger::Builder::new();
    builder.parse_filters("northstar=trace");

    builder.format(|buf, record| {
        let mut style = buf.style();

        let timestamp = buf.timestamp_millis();
        let level = buf.default_styled_level(record.metadata().level());

        if let Some(module_path) = record
            .module_path()
            .and_then(|module_path| module_path.find(&"::").map(|p| &module_path[p + 2..]))
        {
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
                "{}: {:<5}: {} {}",
                timestamp,
                level,
                style.value(module_path),
                record.args(),
            )
        } else {
            writeln!(buf, "{}: {:<5}: {}", timestamp, level, record.args(),)
        }
    });

    builder.init()
}
