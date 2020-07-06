// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;

// TODO: Generate syscall table for aarch64-unknown-linux-gnu

fn main() {
    let current_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("Failed to get CARGO_CFG_TARGET_OS");
    let target_os_dir = match target_os.as_str() {
        "linux" => "linux-x86",
        "android" => "aarch64-linux-android",
        _ => return, // minijail cannot be built for non linux systems
    };

    cc::Build::new()
        .define("ALLOW_DEBUG_LOGGING", "1")
        .define("PRELOADPATH", "\"invalid\"")
        .file(format!("libminijail/{}/libconstants.gen.c", target_os_dir))
        .file(format!("libminijail/{}/libsyscalls.gen.c", target_os_dir))
        .file("libminijail/bpf.c")
        .file("libminijail/util.c")
        .file("libminijail/signal_handler.c")
        .file("libminijail/syscall_filter.c")
        .file("libminijail/syscall_wrapper.c")
        .file("libminijail/system.c")
        .file("libminijail/libminijail.c")
        .include(format!("{}/libminijail", current_dir))
        .compile("minijail");

    println!("cargo:rustc-link-lib=static=minijail");
}
