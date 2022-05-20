//! Northstar console client

#![deny(clippy::all)]
#![deny(missing_docs)]

use anyhow::{Context, Result};
use clap::Parser;
use northstar_runtime::{api, npk};
use okapi::openapi3::{Components, Contact, Info};
use schemars::{gen::SchemaSettings, JsonSchema};
use std::{fs::write, path::PathBuf, str::FromStr};

/// About string for CLI
fn about() -> &'static str {
    Box::leak(Box::new(format!(
        "Northstar schema API version {}, manifest version {}",
        api::VERSION,
        npk::VERSION
    )))
}

#[derive(JsonSchema)]
struct Message(northstar_runtime::api::model::Message);

#[derive(JsonSchema)]
struct Manifest(northstar_runtime::npk::manifest::Manifest);

enum Model {
    Api,
    Manifest,
}

impl FromStr for Model {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "api" => Ok(Model::Api),
            "manifest" => Ok(Model::Manifest),
            _ => Err(anyhow::anyhow!("invalid model: {}", s)),
        }
    }
}

/// CLI
#[derive(Parser)]
#[clap(name = "schema", author, about = about())]
struct Opt {
    /// Output destination. Defaults to stdout
    #[clap(short, long)]
    output: Option<PathBuf>,

    /// Model to generate
    #[clap(short, long)]
    model: Model,
}

fn main() -> Result<()> {
    let opt = Opt::parse();
    let settings = SchemaSettings::openapi3();
    let mut gen = settings.into_generator();

    let (description, version) = match opt.model {
        Model::Api => {
            gen.root_schema_for::<Message>();
            ("Northstar API", api::VERSION)
        }
        Model::Manifest => {
            gen.root_schema_for::<Manifest>();
            ("Northstar NPK", npk::VERSION)
        }
    };

    let schemas = gen
        .definitions()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone().into_object()))
        .collect();

    let spec = okapi::openapi3::OpenApi {
        openapi: "3.0.0".into(),
        info: Info {
            title: "Northstar".into(),
            version: version.to_string(),
            description: Some(description.into()),
            contact: Some(Contact {
                name: Some("ESRLabs".into()),
                url: Some("http://www.github.com/esrlabs/northstar".into()),
                email: Some("info@esrlabs.com".into()),
                ..Default::default()
            }),
            ..Default::default()
        },
        components: Some(Components {
            schemas,
            ..Default::default()
        }),
        ..Default::default()
    };

    let schema = serde_json::to_string_pretty(&spec)?;
    match opt.output {
        Some(path) => {
            write(path, schema.as_bytes()).context("failed to write")?;
        }
        None => println!("{}", schema),
    }
    Ok(())
}
