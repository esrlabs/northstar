fn main() {
    #[cfg(feature = "seccomp")]
    generate_seccomp();
}

#[cfg(feature = "seccomp")]
fn generate_seccomp() {
    use std::{env, fs, io::Write, path};

    fn generate() -> anyhow::Result<()> {
        let lines = bindgen::Builder::default()
            .header_contents("syscall.h", "#include <sys/syscall.h>")
            .allowlist_var("SYS_[0-9a-zA-Z_]+")
            .generate()
            .expect("failed to generate syscall bindings")
            .to_string();
        let lines: Vec<&str> = lines
            .lines()
            .filter(|s| s.starts_with("pub const SYS_"))
            .collect();

        let out_path = path::PathBuf::from(env::var("OUT_DIR")?);
        let mut f = fs::File::create(out_path.join("syscall_bindings.rs"))?;

        f.write_all(lines.join("\n").as_bytes())?;
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
            .layout_tests(false)
            .allowlist_type("seccomp_data")
            .allowlist_type("sock_fprog")
            .allowlist_var("BPF_ABS")
            .allowlist_var("BPF_AND")
            .allowlist_var("BPF_ALU")
            .allowlist_var("BPF_IMM")
            .allowlist_var("BPF_IND")
            .allowlist_var("BPF_JEQ")
            .allowlist_var("BPF_JMP")
            .allowlist_var("BPF_NEG")
            .allowlist_var("BPF_K")
            .allowlist_var("BPF_LD")
            .allowlist_var("BPF_LDX")
            .allowlist_var("BPF_MEM")
            .allowlist_var("BPF_OR")
            .allowlist_var("BPF_RET")
            .allowlist_var("BPF_ST")
            .allowlist_var("BPF_W")
            .allowlist_var("BPF_MAXINSNS")
            .allowlist_var("AUDIT_ARCH_X86_64")
            .allowlist_var("AUDIT_ARCH_AARCH64")
            .generate()
            .expect("failed to generate seccomp bindings")
            .write_to_file(out_path.join("seccomp_bindings.rs"))?;
        Ok(())
    }

    generate().expect("failed to generate seccomp bindings");
}
