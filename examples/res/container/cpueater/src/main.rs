// Copyright (c) 2020 E.S.R.Labs. All rights reserved.
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

use std::env::var;

#[warn(clippy::empty_loop)]
fn main() {
    logd_logger::builder()
        .parse_filters("cpueater")
        .tag("cpueater")
        .init();

    let version = var("VERSION").expect("Failed to read VERSION");
    let threads = var("THREADS")
        .expect("Failed to read THREADS")
        .parse::<i32>()
        .expect("Invalid thread count");

    log::debug!("Eating CPU with {} threads (v{})!", threads, version);

    for _ in 0..threads {
        std::thread::spawn(move || loop {
            let (tx, rx) = std::sync::mpsc::channel();
            tx.send(0).expect("Channel error");
            rx.recv().expect("Channel error");
        });
    }

    loop {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(0).expect("Channel error");
        rx.recv().expect("Channel error");
    }
}
