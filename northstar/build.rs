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

fn main() {
    #[cfg(feature = "rt-island")]
    generate_seccomp();

    #[cfg(feature = "hello-world")]
    package_hello_example().expect("Failed to package hello-world");
}

#[cfg(feature = "rt-island")]
fn generate_seccomp() {
    generate_syscall_bindings().expect("Failed to generate syscall bindings");
    #[cfg(feature = "rt-island")]
    generate_seccomp_bindings().expect("Failed to generate seccomp bindings");
    #[cfg(feature = "rt-island")]
    generate_audit_bindings().expect("Failed to generate audit bindings");
}

#[cfg(feature = "rt-island")]
fn generate_syscall_bindings() -> anyhow::Result<()> {
    use regex::Regex;
    use std::{fs::OpenOptions, io::Write};

    let syscall_regex: Regex = Regex::new("SYS_[0-9a-zA-Z_]+").expect("Invalid regex");
    let rhs_regex: Regex = Regex::new(" = [0-9]+;").expect("Invalid regex");
    let value_regex: Regex = Regex::new("[0-9]+").expect("Invalid regex");

    // get syscall strings and matching numbers
    let lines: Vec<String> = bindgen::Builder::default()
        .header_contents("syscall_wrapper.h", "#include <sys/syscall.h>")
        .generate()
        .expect("Failed to generate syscall bindings")
        .to_string()
        .lines()
        .filter(|l| syscall_regex.is_match(l))
        .map(|s| s.to_string())
        .collect();
    let mut names: Vec<String> = lines
        .iter()
        .filter_map(|l| syscall_regex.find(l).map(|m| m.as_str().to_string()))
        .collect();
    for name in &mut names {
        name.replace_range(..4, ""); // remove leading "SYS_"
    }
    let values: Vec<nix::libc::c_long> = lines
        .iter()
        .filter_map(|l| rhs_regex.find(l).map(|m| m.as_str()))
        .filter_map(|l| value_regex.find(l).map(|m| m.as_str()))
        .filter_map(|l| l.parse().ok())
        .collect();
    assert_eq!(
        names.len(),
        values.len(),
        "Mismatch in number of syscall names and syscall values"
    );

    let out_path = std::path::PathBuf::from(
        std::env::var("OUT_DIR").expect("Environment variable 'OUT_DIR' is not set"),
    );
    let mut f = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(&out_path.join("syscall_bindings.rs"))?;

    // write static map that associates syscall strings with syscall numbers
    writeln!(f, "lazy_static::lazy_static! {{")?;
    writeln!(f, "    static ref SYSCALL_MAP: std::collections::HashMap<&'static str, nix::libc::c_long> = {{")?;
    writeln!(f, "        let mut map = std::collections::HashMap::new();")?;
    for (name, value) in names.iter().zip(values.iter()) {
        writeln!(f, "        map.insert(\"{}\", {});", name, value)?;
    }
    writeln!(f, "        map")?;
    writeln!(f, "    }};")?;
    writeln!(f, "}}")?;

    Ok(())
}

#[cfg(feature = "rt-island")]
pub fn generate_seccomp_bindings() -> anyhow::Result<()> {
    let out_path = std::path::PathBuf::from(
        std::env::var("OUT_DIR").expect("Environment variable 'OUT_DIR' is not set"),
    );
    bindgen::Builder::default()
        .header_contents(
            "seccomp_wrapper.h",
            "#include <linux/seccomp.h>\n#include <linux/filter.h>",
        )
        .allowlist_type("seccomp_data")
        .allowlist_type("sock_fprog")
        .allowlist_var("BPF_ABS")
        .allowlist_var("BPF_JEQ")
        .allowlist_var("BPF_JMP")
        .allowlist_var("BPF_K")
        .allowlist_var("BPF_LD")
        .allowlist_var("BPF_RET")
        .allowlist_var("BPF_W")
        .allowlist_var("SECCOMP_RET_ALLOW")
        .allowlist_var("SECCOMP_RET_LOG")
        .allowlist_var("SECCOMP_RET_KILL")
        .generate()
        .expect("Failed to generate seccomp bindings")
        .write_to_file(&out_path.join("seccomp_bindings.rs"))
        .expect("Failed to write seccomp bindings");
    Ok(())
}

#[cfg(feature = "rt-island")]
pub fn generate_audit_bindings() -> anyhow::Result<()> {
    let out_path = std::path::PathBuf::from(
        std::env::var("OUT_DIR").expect("Environment variable 'OUT_DIR' is not set"),
    );
    bindgen::Builder::default()
        .header_contents("audit_wrapper.h", "#include <linux/audit.h>")
        .allowlist_var("AUDIT_ARCH_X86_64")
        .generate()
        .expect("Failed to generate audit bindings")
        .write_to_file(&out_path.join("audit_bindings.rs"))
        .expect("Failed to write audit bindings");
    Ok(())
}

#[cfg(feature = "hello-world")]
pub fn package_hello_example() -> anyhow::Result<()> {
    use anyhow::Context;
    use npk::npk;
    use std::{env, fs, path::Path};
    use tokio::runtime;

    const MANIFEST: &str = r#"name: hello-world
version: 0.0.1
uid: 1000
gid: 1000
init: /bin/sh
args:
  - "-c"
  - "echo Hello World!"
io:
  stdout: pipe
mounts:
  /bin:
    host: /bin
  /lib:
    host: /lib
  /lib64:
    host: /lib64"#;

    const MANIFEST_ANDROID: &str = r#"name: hello-world
version: 0.0.1
uid: 1000
gid: 1000
init: /system/bin/sh
io:
  stdout: pipe
args:
  - "-c"
  - "echo Hello World!"
mounts:
  /system:
    host: /system"#;

    let out_dir = env::var("OUT_DIR").context("Failed to read OUT_DIR")?;
    let out_dir = Path::new(&out_dir);

    let root_dir = out_dir.join("root");
    fs::create_dir_all(&root_dir).context("Failed to create root dir")?;

    let manifest = match env::var("CARGO_CFG_TARGET_OS")
        .context("Failed to read CARGO_CFG_TARGET_OS")?
        .as_str()
    {
        "android" => MANIFEST_ANDROID,
        _ => MANIFEST,
    };
    let manifest_file = out_dir.join("manifest.yaml");
    std::fs::write(&manifest_file, &manifest).context("Failed to create manifest")?;

    runtime::Builder::new_multi_thread()
        .enable_io()
        .build()?
        .block_on(npk::pack_with(
            &manifest_file,
            &root_dir,
            &out_dir,
            None,
            npk::SquashfsOpts {
                comp: None,
                block_size: None,
            },
        ))?;
    Ok(())
}
