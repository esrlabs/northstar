// Copyright (c) 2021 ESRLabs
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

use super::{ENV_NAME, ENV_VERSION};
use std::ffi::CString;

pub(super) fn args(
    manifest: &npk::manifest::Manifest,
) -> Option<(CString, Vec<CString>, Vec<CString>)> {
    let init = CString::new(manifest.init.as_ref()?.to_str()?).ok()?;
    let mut argv = vec![init.clone()];
    if let Some(ref args) = manifest.args {
        for arg in args {
            argv.push(CString::new(arg.as_bytes()).ok()?);
        }
    }

    let mut env = manifest.env.clone().unwrap_or_default();
    env.insert(ENV_NAME.to_string(), manifest.name.to_string());
    env.insert(ENV_VERSION.to_string(), manifest.version.to_string());
    let env = env
        .iter()
        .map(|(k, v)| CString::new(format!("{}={}", k, v)).ok())
        .collect::<Option<Vec<CString>>>()?;

    Some((init, argv, env))
}
