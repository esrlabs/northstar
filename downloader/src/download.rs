// Copyright (c) 2020 E.S.R.Labs. All rights reserved.
//
// NOTICE:  All information contained herein is, and remains
// the property of E.S.R.Labs and its suppliers, if any.
// The intellectual and technical concepts contained herein are
// proprietary to E.S.R.Labs and its suppliers and may be covered
// by German and Foreign Patents, patents in process, and are protected
// by trade secret or copyright law.
// Dissemination of this information or reproduction of this material
// is strictly forbidden unless prior written permission is obtained
// from E.S.R.Labs.

use crate::REMOTE_UPDATE_SERVER;
use anyhow::{anyhow, Context, Result};
use async_std::{
    fs,
    path::{Path, PathBuf},
    prelude::*,
    sync, task,
};
use log::*;
use north_common::manifest::Version;
use pgp::{types::KeyTrait, Deserializable, SignedPublicKey, StandaloneSignature};
use reqwest::{blocking::Client, header, Proxy};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt, time};
use url::Url;

#[derive(Debug)]
pub enum UpdateEvent {
    ContentLengthKnown(u64),
    SignatureValid(String),
    SignatureInvalid(String),
}

async fn updater() -> sync::Sender<UpdateEvent> {
    let (tx, rx) = sync::channel::<UpdateEvent>(100);

    task::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                UpdateEvent::ContentLengthKnown(len) => debug!("Content length received: {}", len),
                UpdateEvent::SignatureInvalid(_) => debug!("Signature invalid"),
                UpdateEvent::SignatureValid(_) => debug!("Signature valid"),
            }
        }
    });

    tx
}

lazy_static::lazy_static! {
    static ref CLIENT: Client = {
        let catcher = || {
            Client::builder()
                .gzip(false)
                .proxy(Proxy::custom(|url| env_proxy::for_url(url).to_url()))
                .timeout(time::Duration::from_secs(30))
                .build()
        };
        catcher().expect("not correctly inititialized")
    };
}

#[derive(Debug)]
pub enum PgpPublicKey {
    Builtin,
}

impl PgpPublicKey {
    /// Retrieve the key.
    pub fn key(&self) -> &SignedPublicKey {
        unimplemented!()
    }

    #[allow(dead_code)]
    pub fn show_key(&self) -> Result<Vec<String>> {
        fn format_hex(bytes: &[u8], separator: &str, every: usize) -> Result<String> {
            use std::fmt::Write;
            let mut ret = String::new();
            let mut wait = every;
            for b in bytes.iter() {
                if wait == 0 {
                    ret.push_str(separator);
                    wait = every;
                }
                wait -= 1;
                write!(ret, "{:02X}", b)?;
            }
            Ok(ret)
        }
        let mut ret = Vec::new();
        ret.push(format!("from {}", self));
        let key = self.key();
        let keyid = format_hex(&key.key_id().to_vec(), "-", 4)?;
        let algo = key.algorithm();
        let fpr = format_hex(&key.fingerprint(), " ", 2)?;
        let uid0 = key
            .details
            .users
            .get(0)
            .map(|u| u.id.id())
            .unwrap_or("<No User ID>");
        ret.push(format!("  {:?}/{} - {}", algo, keyid, uid0));
        ret.push(format!("  Fingerprint: {}", fpr));
        Ok(ret)
    }
}

impl fmt::Display for PgpPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Builtin => write!(f, "builtin northstar download key"),
        }
    }
}

#[derive(Clone, Default, Hash, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct ModuleInfo {
    /// Name of container
    pub name: String,
    /// Container version
    pub version: Version,
    /// Packed container file
    pub file: String,
}

pub(crate) type VersionManifest = HashMap<String, (String, Version)>;

pub async fn download_updates(
    ids_with_versions: &HashMap<String, Version>,
    download_dir: &Path,
) -> Result<String> {
    let tx_updater = updater().await;
    let updates = find_available_updates(ids_with_versions).await?;

    if updates.is_empty() {
        info!("No update available");
        return Ok("No update available".to_string());
    }
    let update_count = updates.len();
    let mut succesfull_download_cnt = 0usize;
    for (_remote_name, remote_url) in updates {
        debug!("try to download: {}", _remote_name);
        match download_and_check(&remote_url[..], download_dir, &tx_updater).await {
            Ok(downloaded_file) => {
                debug!("downloaded {:?}", downloaded_file);
                succesfull_download_cnt += 1;
            }
            Err(e) => warn!("could not download {} ({})", _remote_name, e),
        }
    }
    Ok(format!(
        "{} from {} updates found and downloaded",
        succesfull_download_cnt, update_count
    ))
}

/// check remote server for updated versions
/// return a list of (name, file_name) pairs
async fn find_available_updates(
    ids_with_versions: &HashMap<String, Version>,
) -> Result<Vec<(String, String)>> {
    let version_info = download_version_manifest().await?;
    trace!("Downloaded version info {:?}", version_info);
    let mut available_updates: Vec<(String, String)> = Vec::new();
    // check installed apps
    for (id, image_version) in ids_with_versions.iter() {
        debug!(
            "Checking local images with name {} and version {}",
            id, image_version
        );

        if let Some((new_file_name, potential_new_version)) = version_info.get(id) {
            if potential_new_version > image_version {
                info!("Update available for: {}", id);
                available_updates.push((id.clone(), new_file_name.clone()));
            } else {
                debug!(
                    "matching image for {} found but no update (was {})",
                    id, potential_new_version
                );
            }
        }
    }
    Ok(available_updates)
}

pub fn verify_signature(buffer: &[u8], signature: &str) -> Result<bool> {
    //debug!("Verifying signature of {:02X?} with signature {}", buffer, signature);
    let (signatures, _) = StandaloneSignature::from_string_many(signature)?;
    for signature in signatures {
        match signature {
            Ok(signature) => {
                let actual_key = PgpPublicKey::Builtin.key();
                if actual_key.is_signing_key() && signature.verify(&actual_key, &buffer).is_ok() {
                    debug!("Signature verified with builtin key");
                    return Ok(true);
                }

                for sub_key in &actual_key.public_subkeys {
                    if sub_key.is_signing_key() {}
                    if sub_key.is_signing_key() && signature.verify(sub_key, &buffer).is_ok() {
                        debug!("Signature verified with subkey");
                        return Ok(true);
                    }
                }
            }
            Err(e) => {
                error!("Error in signature: {}", e);
                continue;
            }
        }
    }
    warn!("Could not verify signature with given key");
    Ok(false)
}

pub async fn check_signature(input_path: &PathBuf, signature: &str) -> Result<bool> {
    debug!("Verifying signature of {:?}", input_path.display());

    let mut buffer = Vec::new();
    let mut input = fs::File::open(input_path)
        .await
        .context("Failed to open input")?;
    input
        .read_to_end(&mut buffer)
        .await
        .context("Failed to read input")?;

    let now = time::Instant::now();
    let r = verify_signature(&buffer, signature)?;
    debug!(
        "Verifying signature of {} took {} us",
        input_path.display(),
        now.elapsed().as_micros()
    );
    Ok(r)
}

fn parse_manifest(content: &str) -> Result<VersionManifest> {
    let version_list: Vec<ModuleInfo> = serde_yaml::from_str(content)?;
    let mut manifest = VersionManifest::new();
    for module_version in version_list.iter() {
        let version = &module_version.version;
        manifest.insert(
            module_version.name.clone(),
            (module_version.file.clone(), version.clone()),
        );
    }
    Ok(manifest)
}

#[derive(Debug)]
struct Download {
    url: Url,
    dest_file: PathBuf,
    download_dir: PathBuf,
    update_channel: sync::Sender<UpdateEvent>,
}

impl Download {
    pub async fn new(
        file_name: &str,
        dir: impl AsRef<Path>,
        update_channel: sync::Sender<UpdateEvent>,
    ) -> Result<Self> {
        let url_string = &format!("{}/{}", REMOTE_UPDATE_SERVER, file_name)[..];
        let url = Url::parse(&url_string)
            .with_context(|| format!("Failed to parse url: {}", url_string))?;

        ensure_dir_exists(&dir).await?;
        let download_dir = dir.as_ref().to_path_buf();

        Ok(Download {
            url,
            dest_file: dir.as_ref().join(file_name),
            download_dir,
            update_channel,
        })
    }

    pub async fn download(&mut self) -> Result<PathBuf> {
        debug!("Starting download of {}", self.url);

        let dest = self.dest_file.clone();
        let url = self.url.clone();
        let tx = self.update_channel.clone();
        task::spawn_blocking(|| async move {
            if dest.exists().await {
                fs::remove_file(&dest)
                    .await
                    .with_context(|| format!("Could not remove file {:?}", &dest))?;
            }

            let mut read = match url.scheme() {
                "file" => {
                    let src = url
                        .to_file_path()
                        .map_err(|_| anyhow!("Incorrect file url: '{}'", url))?;
                    if !src.is_file() {
                        return Err(anyhow!("File not found: {:?}", src));
                    }
                    let f = std::fs::File::open(src).context("Unable to open downloaded file")?;
                    Box::new(f) as Box<dyn std::io::Read>
                }
                "http" | "https" => {
                    debug!("Performing HTTP request to {}", url);
                    let request = CLIENT.get(url.as_str());
                    let response = request.send().context("Failed to send HTTP get request")?;

                    if !response.status().is_success() {
                        let code: u16 = response.status().into();
                        return Err(anyhow!("Error downloading {}: error code {}", url, code));
                    }

                    if let Some(len) = response.headers().get(header::CONTENT_LENGTH) {
                        let len = len.to_str()?.parse::<u64>()?;
                        tx.send(UpdateEvent::ContentLengthKnown(len)).await;
                    }
                    Box::new(response) as Box<dyn std::io::Read>
                }
                _ => return Err(anyhow!("Unsupported url type {}", url)),
            };

            std::fs::File::create(&dest)
                .with_context(|| format!("Failed to open {:?}", dest))
                .and_then(|mut dest| std::io::copy(&mut read, &mut dest).context("Failed to copy"))
        })
        .await
        .await?;

        Ok(self.dest_file.clone())
    }
}

pub(crate) async fn download_version_manifest() -> Result<VersionManifest> {
    let packages_yaml = format!("packages-{}.yaml", env!("VERGEN_TARGET_TRIPLE"));
    let remote_url = format!("{}/{}", REMOTE_UPDATE_SERVER, packages_yaml);
    debug!("Downloading package list from {}", remote_url);
    let response = task::spawn_blocking(move || reqwest::blocking::get(&remote_url)).await?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(anyhow!("Version manifest not found"));
    }
    if status != reqwest::StatusCode::OK {
        return Err(anyhow!(
            "Version manifest download failed with status {}",
            status
        ));
    }
    let manifest_content = response.text()?;
    trace!("Downloaded manifest: {}", manifest_content);
    parse_manifest(&manifest_content[..])
}

pub(crate) async fn download_signature(
    file_name: &str,
    download_dir: impl AsRef<Path>,
    update_channel: sync::Sender<UpdateEvent>,
) -> Result<(String, PathBuf)> {
    let mut download =
        Download::new(&format!("{}.asc", file_name), download_dir, update_channel).await?;
    debug!("Downloading signature from {}", download.url);

    let file = download.download().await?;
    let signature = read_to_string(&file).await?;
    Ok((signature, file))
}

/// this will download 3 files:
/// * the actuale package found at `url_str`
/// * a file that contains the checksum (ends in USED_CRYPTO_HASH)
/// * and the signature of the package (ends in `.asc`)
///
/// verifies the signature
/// returns the path to the downloaded file and its crypto hash
pub async fn download_and_check(
    file_name: &str,
    download_dir: impl AsRef<Path>,
    update_channel: &sync::Sender<UpdateEvent>,
) -> Result<PathBuf> {
    let mut download = Download::new(file_name, &download_dir, update_channel.clone()).await?;
    let downloaded_file = download.download().await?;
    debug!("Downloaded {}", file_name);

    let (signature, _signature_path) =
        download_signature(&file_name, download_dir, update_channel.clone())
            .await
            .context(format!("Downloading signature failed for {}", download.url))?;
    fs::remove_file(&_signature_path)
        .await
        .with_context(|| format!("Could not remove file {:?}", &_signature_path))?;
    if check_signature(&downloaded_file, &signature)
        .await
        .map_err(|_| anyhow!("Failed to check signature"))?
    {
        update_channel
            .send(UpdateEvent::SignatureValid(download.url.to_string()))
            .await;
        Ok(downloaded_file)
    } else {
        update_channel
            .send(UpdateEvent::SignatureInvalid(download.url.to_string()))
            .await;
        debug!("Signature check passed");
        debug!("Signature check failed");
        Err(anyhow!("Signature check failed for {}", file_name))
    }
}

pub async fn ensure_dir_exists<P: AsRef<Path>>(path: P) -> Result<bool> {
    if !path.as_ref().is_dir().await {
        fs::create_dir_all(path.as_ref())
            .await
            .map(|()| true)
            .with_context(|| format!("Could not create dir: {:?}", path.as_ref()))
    } else {
        Ok(false)
    }
}

async fn read_to_string(path: &Path) -> Result<String> {
    fs::read_to_string(path)
        .await
        .with_context(|| format!("Error reading file: {:?}", path))
}
