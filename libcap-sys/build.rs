// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("Failed to get CARGO_CFG_TARGET_OS");

    match target_os.as_str() {
        "linux" | "android" => (),
        _ => return,
    };

    let sources = &[
        "libcap/cap_alloc.c",
        "libcap/cap_flag.c",
        "libcap/cap_proc.c",
        "libcap/cap_text.c",
    ];

    let mut build = cc::Build::new();

    build.flag("-Ilibcap/include").files(sources).compile("cap");

    sources
        .iter()
        .for_each(|s| println!("cargo:rerun-if-changed={}", s));

    println!("cargo:rustc-link-lib=static=cap");
}
