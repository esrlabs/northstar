/// Initialize the logger
#[cfg(target_os = "android")]
pub fn init() {
    android_logd_logger::builder()
        .tag("northstar")
        .prepend_module(false)
        .parse_filters("northstar=debug")
        .init();
}

/// Initialize the logger. To synchronize the log output of the different process, the records
/// are sent via a unix datagram socket to a thread that prints the log records.
#[cfg(not(target_os = "android"))]
#[allow(clippy::print_with_newline)]
pub fn init() {
    use console::{style, Color};
    use log::{Level, Log};
    use serde::{Deserialize, Serialize};
    use std::{os::unix::net::UnixDatagram, thread};
    use time::{format_description::FormatItem, macros::format_description, OffsetDateTime};

    const TIMESETAMP_FORMAT: &[FormatItem<'static>] =
        format_description!("[hour]:[minute]:[second].[subsecond digits:3]");

    /// A log record that is serialized and sent to the logger thread.
    #[derive(Debug, Serialize, Deserialize)]
    struct Record {
        /// Timestamp.
        timestamp: OffsetDateTime,
        /// Log level.
        level: Level,
        /// Thread group id.
        tgid: u32,
        /// Taget string.
        target: String,
        /// Log message.
        message: String,
    }

    /// Generate a color of `self`.
    trait HashColor {
        fn color(&self) -> Color;
    }

    impl HashColor for &str {
        fn color(&self) -> Color {
            let hash = self.bytes().fold(42u8, |c, x| c ^ x);
            Color::Color256(hash)
        }
    }

    impl HashColor for u32 {
        fn color(&self) -> Color {
            // Some colors are hard to read on (at least) dark terminals
            // and I consider some others as ugly ;-)
            let color = match *self as u8 {
                c @ 0..=1 => c + 2,
                c @ 16..=21 => c + 6,
                c @ 52..=55 | c @ 126..=129 => c + 4,
                c @ 163..=165 | c @ 200..=201 => c + 3,
                c @ 207 => c + 1,
                c @ 232..=240 => c + 9,
                c => c,
            };
            Color::Color256(color)
        }
    }

    let (logger, client) =
        UnixDatagram::pair().expect("failed to create unix datagram socket pair");

    // Spawn a thread that reads from the socket and prints the log records.
    thread::spawn(move || {
        let mut buffer = vec![0u8; 64 * 1024];
        let mut target_size = 30;
        loop {
            let record = logger
                .recv(&mut buffer)
                .map(|n| &buffer[..n])
                .expect("logging socket error");
            let record =
                bincode::deserialize::<Record>(record).expect("failed to deserialize log record");
            let timestamp = record
                .timestamp
                .format(TIMESETAMP_FORMAT)
                .expect("failed to format timestamp");
            let target = style(&record.target)
                .bold()
                .fg(record.target.as_str().color());
            let level_color = match record.level {
                Level::Error => Color::Red,
                Level::Warn => Color::Yellow,
                Level::Info => Color::Green,
                Level::Debug => Color::Color256(243),
                Level::Trace => Color::White,
            };
            let level = style(record.level).bold().fg(level_color);
            let message = record.message;
            target_size = target_size.max(record.target.len());

            let tgid = style("⬤").fg(record.tgid.color());
            print!(
                "{timestamp} {target:>s$} {tgid}  {level:<5}: {message}\n",
                s = target_size
            );
        }
    });

    struct Logger(UnixDatagram);

    impl Log for Logger {
        fn enabled(&self, metadata: &log::Metadata) -> bool {
            metadata.level() <= log::max_level()
        }

        fn log(&self, record: &log::Record) {
            let timestamp = OffsetDateTime::now_utc();
            let level = record.level();
            let tgid = std::process::id();
            let target = Option::from(record.target().is_empty())
                .map(|_| record.target())
                .or_else(|| record.module_path())
                .map(|module_path| {
                    module_path
                        .strip_prefix("northstar::")
                        .unwrap_or(module_path)
                })
                .map(|module_path| {
                    module_path
                        .strip_prefix("northstar_runtime::")
                        .unwrap_or(module_path)
                })
                .unwrap_or_default()
                .to_owned();
            let message = record.args().to_string();

            let record = Record {
                timestamp,
                level,
                tgid,
                target,
                message,
            };

            let message = bincode::serialize(&record).expect("failed to serialize log record");
            self.0
                .send(&message)
                .map(drop)
                .expect("failed to send log record");
        }

        fn flush(&self) {}
    }

    log::set_boxed_logger(Box::new(Logger(client))).expect("failed to set logger");
    log::set_max_level(log::LevelFilter::Debug);
}
