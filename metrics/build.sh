#!/bin/bash
# Build metric container: prometheus and grafana

set -x

mkdir -p "../target/northstar/repository"

wget "https://github.com/prometheus/prometheus/releases/download/v2.35.0/prometheus-2.35.0.linux-amd64.tar.gz"
tar xzf "prometheus-2.35.0.linux-amd64.tar.gz"
cp "prometheus-config.yml" "prometheus-2.35.0.linux-amd64"
cargo run --bin "northstar-sextant" -- pack -m "prometheus-manifest.yml" -r "prometheus-2.35.0.linux-amd64" -o "../target/northstar/repository" -k "../examples/northstar.key"
rm "prometheus-2.35.0.linux-amd64.tar.gz"
rm -r "prometheus-2.35.0.linux-amd64"

wget "https://dl.grafana.com/enterprise/release/grafana-enterprise-8.5.3.linux-amd64.tar.gz"
tar xzf "grafana-enterprise-8.5.3.linux-amd64.tar.gz"
cargo run --bin "northstar-sextant" -- pack -m "grafana-manifest.yml" -r "grafana-8.5.3" -o "../target/northstar/repository" -k "../examples/northstar.key"
rm -r "grafana-8.5.3"
rm "grafana-enterprise-8.5.3.linux-amd64.tar.gz"