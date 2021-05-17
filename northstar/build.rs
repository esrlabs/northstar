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
    use std::{env, fs, io::Write, path};

    fn generate() -> anyhow::Result<()> {
        let target = std::env::var("TARGET").unwrap();

        // Need some extra include path for the cross images for aarch64 gnu and musl
        let extra_arg = match target.as_str() {
            "aarch64-unknown-linux-gnu" => "-I/usr/aarch64-linux-gnu/include",
            "aarch64-unknown-linux-musl" => "-I/usr/local/aarch64-linux-musl/include",
            _ => "",
        };

        let lines = bindgen::Builder::default()
            .header_contents("syscall.h", "#include <sys/syscall.h>")
            .allowlist_var("SYS_[0-9a-zA-Z_]+")
            .clang_arg(extra_arg)
            .generate()
            .expect("Failed to generate syscall bindings")
            .to_string();
        let lines: Vec<&str> = lines
            .lines()
            .filter(|s| s.starts_with("pub const SYS_"))
            .collect();

        let out_path = path::PathBuf::from(env::var("OUT_DIR")?);
        let mut f = fs::File::create(&out_path.join("syscall_bindings.rs"))?;

        f.write_all(&lines.join("\n").as_bytes())?;
        writeln!(f)?;
        writeln!(f)?;

        // Write static map that associates syscall strings with syscall numbers
        writeln!(f, "lazy_static::lazy_static! {{")?;
        writeln!(
            f,
            "    pub(super) static ref SYSCALL_MAP: std::collections::HashMap<&'static str, u32> = {{"
        )?;
        writeln!(f, "        let mut map = std::collections::HashMap::new();")?;
        lines.iter().try_for_each(|l| {
            let mut split = l.split_ascii_whitespace();
            let var = split.nth(2).unwrap().trim_end_matches(':');
            let name = var.replace("SYS_", "");
            writeln!(f, "        map.insert(\"{}\", {});", name, var)?;
            std::io::Result::Ok(())
        })?;
        writeln!(f, "        map")?;
        writeln!(f, "    }};")?;
        writeln!(f, "}}")?;

        let out_path = std::path::PathBuf::from(env::var("OUT_DIR")?);
        bindgen::Builder::default()
            .header_contents(
                "seccomp.h",
                r#"#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>"#,
            )
            .clang_arg(extra_arg)
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
            .allowlist_var("AUDIT_ARCH_X86_64")
            .allowlist_var("AUDIT_ARCH_AARCH64")
            .generate()
            .expect("Failed to generate seccomp bindings")
            .write_to_file(&out_path.join("seccomp_bindings.rs"))?;
        Ok(())
    }

    generate().expect("Failed to generate seccomp bindings");
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
