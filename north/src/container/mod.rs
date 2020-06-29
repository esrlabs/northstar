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

use async_std::path::PathBuf;
use north_common::manifest::Manifest;

#[cfg(any(target_os = "android", target_os = "linux"))]
mod linux;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub use linux::{install, install_all, uninstall};

#[cfg(not(any(target_os = "android", target_os = "linux")))]
mod osx;
#[cfg(not(any(target_os = "android", target_os = "linux")))]
pub use osx::{install, install_all, uninstall};

#[cfg(any(target_os = "android", target_os = "linux"))]
mod hashes;

#[derive(Debug)]
pub struct Container {
    pub manifest: Manifest,
    pub root: PathBuf,
    pub data: PathBuf,
}
