use std::{collections::HashMap, time};

use anyhow::{anyhow, Result};
use axum::routing::get;
use itertools::Itertools;
use log::{info, warn};
use prometheus::{Encoder, IntGauge, Opts, Registry};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::task;
use url::Url;

use crate::common::container::Container;

lazy_static::lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
}

const fn default_scrape_interval() -> time::Duration {
    time::Duration::from_secs(5)
}

type Path = Vec<String>;

/// Format something as a prometheus name.
trait ToPrometheusName {
    fn to_name(&self) -> String;
}

impl<T> ToPrometheusName for T
where
    T: ToString,
{
    fn to_name(&self) -> String {
        let name = self.to_string();
        name.chars()
            .map(|c| {
                // In theory the colon is allowed too but reserved for user defined
                // recording rules
                if c.is_ascii_alphanumeric() || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    }
}

/// Metrics configuration
#[derive(Clone, Debug, Deserialize)]
pub struct Configuration {
    /// Prometheus endpoint
    pub url: Url,
    /// Scrape interval
    #[serde(with = "humantime_serde", default = "default_scrape_interval")]
    pub scrape_interval: time::Duration,
}

impl Default for Configuration {
    fn default() -> Self {
        Configuration {
            url: Url::parse("http://localhost:8080/metrics").expect("this is a bug"),
            scrape_interval: default_scrape_interval(),
        }
    }
}

#[derive(Debug)]
pub struct Gauge {
    inner: Box<IntGauge>,
}

impl Gauge {
    pub fn new(container: &Container, path: &Path) -> Gauge {
        let fqn = path.join("_");
        let opts = Opts::new(fqn.clone(), fqn)
            .const_label("container", container.to_name())
            .const_label("path", path.iter().skip(1).join("_"));
        let inner = Box::new(IntGauge::with_opts(opts).expect("failed to create gauge"));
        REGISTRY
            .register(inner.clone())
            .expect("metric can be registered");
        Gauge { inner }
    }
}

impl Drop for Gauge {
    fn drop(&mut self) {
        REGISTRY
            .unregister(self.inner.clone())
            .expect("failed to unregister metric");
    }
}

#[derive(Debug)]
pub struct Metrics {
    gauges: HashMap<Path, Gauge>,
}

impl<'a> Metrics {
    pub async fn new(configuration: &Configuration) -> Result<Metrics> {
        assert!(configuration.url.scheme() == "http");

        let url = configuration.url.clone();
        let path = url.path().to_string();
        let addrs = url.socket_addrs(|| None)?;
        let addr = *addrs
            .first()
            .ok_or_else(|| anyhow!("Invalid prometheus URL: {}", url))?;
        info!("Starting metrics server on {}", url);

        task::spawn(async move {
            let app = axum::Router::new().route(&path, get(metrics));
            axum::Server::bind(&addr)
                .serve(app.into_make_service())
                .await
                .expect("failed to serve metrics");
        });

        Ok(Metrics {
            gauges: HashMap::default(),
        })
    }

    /// Add metrics data for container specified by `data`.
    pub(crate) fn add<T: Serialize>(&mut self, container: &Container, name: &str, data: T) {
        let value = serde_json::to_value(data).expect("json error");
        let mut path = vec![container.to_name(), name.to_string()];
        self.register(container, &mut path, value);
    }

    /// Remove container from the metrics by unregistering all elements that
    /// belong to `container`.
    pub fn remove(&mut self, container: &Container) {
        // Remove all gauges with a path starting with `container`
        let container = container.to_name();
        self.gauges
            .retain(|path, _| path.get(0).map(|c| c != &container).unwrap_or(false));
    }

    fn register(&mut self, container: &Container, path: &mut Path, value: Value) {
        match value {
            Value::Number(n) => {
                let value = n.as_i64().unwrap_or(0);
                if let Some(gauge) = self.gauges.get(path) {
                    gauge.inner.set(value);
                } else {
                    let gauge = Gauge::new(container, path);
                    gauge.inner.set(value);
                    self.gauges.insert(path.clone(), gauge);
                }
            }
            Value::Bool(n) => {
                let value = if n { 1 } else { 0 };
                if let Some(gauge) = self.gauges.get(path) {
                    gauge.inner.set(value);
                } else {
                    let gauge = Gauge::new(container, path);
                    gauge.inner.set(value);
                    self.gauges.insert(path.clone(), gauge);
                }
            }
            Value::Array(arr) => {
                for (name, value) in arr.into_iter().enumerate() {
                    path.push(name.to_string());
                    self.register(container, path, value);
                    path.pop();
                }
            }
            Value::Object(map) => {
                for (name, value) in map.into_iter() {
                    path.push(name);
                    self.register(container, path, value);
                    path.pop();
                }
            }
            _ => (),
        }
    }
}

/// Request handler. Serialize prometheus metrics and send them to the client.
async fn metrics() -> String {
    let encoder = prometheus::TextEncoder::new();
    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&REGISTRY.gather(), &mut buffer) {
        warn!("Failed to encode prometheus metrics: {}", e);
    };
    String::from_utf8(buffer).unwrap_or_else(|e| {
        warn!("Failed to serialize metrics from_utf8: {}", e);
        String::default()
    })
}
