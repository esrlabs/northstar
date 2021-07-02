// Copyright (c) 2019 - 2020 ESRLabs
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

//! Conversion of OCI containers to NPK (WIP)
//!
//!
//!
//!
//!
//!
//!

use oci_spec::Spec;
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use thiserror::Error;

use crate::manifest;
use crate::manifest::Bind;
use crate::manifest::Io;
use crate::manifest::Manifest;
use crate::manifest::Mount;
use crate::manifest::MountOption;
use crate::manifest::Output;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid path: {0}")]
    InvalidPath(PathBuf),
    #[error("Failed to load OCI spec: {0}")]
    LoadSpec(anyhow::Error),
    #[error("Failed to load OCI spec from json reader: {0}")]
    LoadSpec2(serde_json::Error),
    #[error("Failed to create temporal file to hold manifest: {0}")]
    ManifestTempFile(std::io::Error),
    #[error("Failed to serialize generated manifest: {0}")]
    ManifestSerialization(serde_yaml::Error),
}

/// Loads the OCI spec from bundle
pub fn load_oci_spec(path: &Path) -> Result<Spec, Error> {
    let path = path
        .to_str()
        .ok_or_else(|| Error::InvalidPath(path.to_owned()))?;
    Spec::load(path).map_err(Error::LoadSpec)
}

/// Loads an OCI spec from a reader
pub fn load_oci_spec_from_reader<R: std::io::Read>(reader: R) -> Result<Spec, Error> {
    serde_json::from_reader(reader).map_err(Error::LoadSpec2)
}

/// Tries to conver an OCI Spec to a Northstar manifest
///
/// WIP
///
/// - map capabilities
/// - map mounts
/// - map cgroups & seccomp
/// - ...
///
/// TODO factor out all the individual conversions
///
///
pub fn convert_oci_spec_to_manifest(oci_spec: Spec) -> Result<Manifest, Error> {
    let mut process_args = oci_spec.process.args.into_iter();

    // The program path should be the first argumment from the list
    let init = process_args.next().map(PathBuf::from);
    let args = {
        let args: Vec<_> = process_args.collect();
        if args.is_empty() {
            None
        } else {
            Some(args)
        }
    };

    // The spec does not specify an identifier for the contaienr, we take the file name for the
    // process as the container name
    let name = if let Some(name) = init
        .as_ref()
        .and_then(|p| p.file_name())
        .and_then(|p| p.to_str())
    {
        name.to_owned()
    } else {
        // TODO find some way to name containers that specify no process, or just return an
        // error
        unimplemented!()
    };

    // TODO this should be some kind of constant
    let version = manifest::Version::parse("1.0.0").unwrap();

    let uid = oci_spec.process.user.uid;
    let gid = oci_spec.process.user.gid;

    // Try to extract the environmant variables
    let env = {
        let env: HashMap<_, _> = oci_spec
            .process
            .env
            .into_iter()
            .map(|var| {
                let name: String = var.chars().take_while(|x| *x != '=').collect();
                let value: String = var.chars().skip_while(|x| *x != '=').skip(1).collect();
                (name, value)
            })
            .collect();
        if env.is_empty() {
            None
        } else {
            Some(env)
        }
    };

    // There is no mapping defined for the next 3 parameters
    //
    // - autostart
    // - cgroups
    // - seccomp
    //
    // TODO map mounts

    let mounts = oci_spec
        .mounts
        .into_iter()
        .filter_map(|m| {
            let target = m.destination;

            if matches!(
                target.as_path().to_str(),
                Some("/proc") | Some("/dev") | Some("/sys")
            ) {
                None
            } else if matches!(target.as_path().to_str(), Some("/dev")) {
                Some((target, Mount::Dev))
            } else {
                Some((
                    target,
                    Mount::Bind(Bind {
                        host: m.source,
                        options: vec![MountOption::Rw].into_iter().collect(),
                    }),
                ))
            }
        })
        .collect();

    // TODO map capabilities

    // TODO map io
    let io = Some(Io {
        stdout: Some(Output::Log {
            level: log::Level::Debug,
            tag: "hello".to_string(),
        }),
        stderr: Some(Output::Pipe),
    });

    Ok(Manifest {
        name,
        version,
        init,
        args,
        uid,
        gid,
        env,
        autostart: None,
        cgroups: None,
        seccomp: None,
        mounts,
        capabilities: None,
        suppl_groups: None,
        io,
    })
}
