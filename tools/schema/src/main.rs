//! Northstar console client

#![deny(clippy::all)]
#![deny(missing_docs)]

use anyhow::{anyhow, Context, Result};
use northstar::api;
use schemars::gen::SchemaSettings;
use std::{fmt::Display, path::PathBuf, str::FromStr};
use structopt::{clap::AppSettings, StructOpt};

/// About string for CLI
fn about() -> &'static str {
    Box::leak(Box::new(format!(
        "Northstar schema API version {}",
        api::model::version()
    )))
}

/// JsonSchema version
#[derive(Clone)]
enum Format {
    OpenApi3,
    Draft07,
    Draft2019_09,
}

impl FromStr for Format {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "openapi3" => Ok(Format::OpenApi3),
            "draft07" => Ok(Format::Draft07),
            "draft2019-09" => Ok(Format::Draft2019_09),
            _ => Err(anyhow!("Invalid format: {}", s)),
        }
    }
}

impl Display for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Format::OpenApi3 => write!(f, "openapi3"),
            Format::Draft07 => write!(f, "draft07"),
            Format::Draft2019_09 => write!(f, "draft2019-09"),
        }
    }
}

/// CLI
#[derive(StructOpt, Clone)]
#[structopt(name = "schema", author, about = about(), global_setting(AppSettings::ColoredHelp))]
struct Opt {
    /// Output destination. Defaults to stdout
    #[structopt(short, long)]
    output: Option<PathBuf>,
    /// Format
    #[structopt(short, long, default_value = "openapi3")]
    format: Format,
}

fn main() -> Result<()> {
    let opt = Opt::from_args();
    let settings = match opt.format {
        Format::OpenApi3 => SchemaSettings::openapi3(),
        Format::Draft07 => SchemaSettings::draft07(),
        Format::Draft2019_09 => SchemaSettings::draft2019_09(),
    };
    let gen = settings.into_generator();
    let schema = gen.into_root_schema_for::<northstar::api::model::Message>();
    let schema = serde_json::to_string_pretty(&schema)?;
    match opt.output {
        Some(path) => {
            std::fs::write(path, schema.as_bytes()).context("Failed to write")?;
        }
        None => println!("{}", schema),
    }
    Ok(())
}
