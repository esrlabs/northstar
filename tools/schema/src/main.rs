//! Northstar console client

#![deny(clippy::all)]
#![deny(missing_docs)]

use anyhow::{Context, Result};
use northstar::api;
use okapi::openapi3::{Components, Contact, Info};
use schemars::{gen::SchemaSettings, JsonSchema};
use std::{fs::write, path::PathBuf, str::FromStr};
use structopt::{clap::AppSettings, StructOpt};

/// About string for CLI
fn about() -> &'static str {
    Box::leak(Box::new(format!(
        "Northstar schema API version {}",
        api::model::version()
    )))
}

#[derive(JsonSchema)]
struct Message(northstar::api::model::Message);

#[derive(JsonSchema)]
struct Manifest(northstar::npk::manifest::Manifest);

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
            _ => Err(anyhow::anyhow!("Invalid model: {}", s)),
        }
    }
}

/// CLI
#[derive(StructOpt)]
#[structopt(name = "schema", author, about = about(), global_setting(AppSettings::ColoredHelp))]
struct Opt {
    /// Output destination. Defaults to stdout
    #[structopt(short, long)]
    output: Option<PathBuf>,

    /// Model to generate
    #[structopt(short, long)]
    model: Model,
}

fn main() -> Result<()> {
    let opt = Opt::from_args();
    let settings = SchemaSettings::openapi3();
    let mut gen = settings.into_generator();

    match opt.model {
        Model::Api => {
            gen.root_schema_for::<Message>();
        }
        Model::Manifest => {
            gen.root_schema_for::<Manifest>();
        }
    }

    let schemas = gen
        .definitions()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone().into_object()))
        .collect();

    let spec = okapi::openapi3::OpenApi {
        openapi: "3.0.0".into(),
        info: Info {
            title: "Northstar".into(),
            version: northstar::api::model::version().to_string(),
            description: Some("Northstar API".into()),
            contact: Some(Contact {
                name: Some("ESRLabs".into()),
                url: Some("http://www.esrlabs.com".into()),
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
            write(path, schema.as_bytes()).context("Failed to write")?;
        }
        None => println!("{}", schema),
    }
    Ok(())
}
