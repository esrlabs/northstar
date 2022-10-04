use anyhow::{Context, Result};
use clap::CommandFactory;
use clap_complete::Shell;
use std::{fs, path::PathBuf};

use crate::Opt;

pub fn completion(output: Option<PathBuf>, shell: Shell) -> Result<()> {
    let mut writer: Box<dyn std::io::Write> = match output {
        Some(path) => {
            println!("Generating {} completions to {}", shell, path.display());
            let file = fs::File::create(&path)
                .with_context(|| format!("failed to create {}", path.display()))?;
            Box::new(file)
        }
        None => Box::new(std::io::stdout()),
    };

    clap_complete::generate(
        shell,
        &mut Opt::command(),
        Opt::command().get_name().to_string(),
        &mut writer,
    );
    Ok(())
}
