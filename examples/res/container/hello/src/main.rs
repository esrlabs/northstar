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

fn main() {
    let hello = std::env::var("HELLO").unwrap_or_else(|_| "unknown".into());
    let version = std::env::var("VERSION").unwrap_or_else(|_| "unknown".into());
    println!("Hello again {} from version {}!", hello, version);
    for i in 0..u64::MAX {
        println!(
            "...and hello again #{} {} from version {}...",
            i, hello, version
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
