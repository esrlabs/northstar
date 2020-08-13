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

use async_std::path::PathBuf;
use std::{fmt, path::Path};
use structopt::StructOpt;

const DEFAULT_CONSOLE_ADDRESS: &str = "127.0.0.1:4242";

lazy_static::lazy_static! {
    #[derive(Debug)]
    pub static ref SETTINGS: Settings = {
        let opt = CliOptions::from_args();
        let mut settings = config::Config::default();

        // Read config file
        // Try the command line config file and fall back to north.toml
        if let Some(config) = opt.config {
            settings.merge(config::File::with_name(&config)).expect("Failed to read configuration");
        } else {
            let config = Path::new("north.toml");
            if config.is_file() {
                settings.merge(config::File::with_name(&config.display().to_string())).expect("Failed to read configuration");
            } else {
                panic!("Failed to find default configuration north.toml");
            }
        }

        // Read environment
        settings.merge(config::Environment::with_prefix("NORTH")).expect("Failed to read environment");

        let debug = opt.debug || settings.get("debug").unwrap_or(false);

        let console_address = opt.console_address.unwrap_or_else(|| {
            settings.get("console_address").unwrap_or_else(|_| DEFAULT_CONSOLE_ADDRESS.into())
        });
        let global_data_dir = opt.global_data_dir || settings.get("global_data_dir").unwrap_or(false);


        let container_dirs = opt.container_dir.unwrap_or_else(|| {
            let dir: Vec<String> = settings.get("directories.container_dirs").expect("Missing directories.container_dirs in configuration");
            dir.iter().map(PathBuf::from).collect()
        });
        let run_dir = opt.run_dir.unwrap_or_else(|| {
            let dir: String = settings.get("directories.run_dir").expect("Missing directories.run_dir in configuration");
            PathBuf::from(dir)
        });
        let data_dir = opt.data_dir.unwrap_or_else(|| {
            let dir: String = settings.get("directories.data_dir").expect("Missing directories.data_dir in configuration");
            PathBuf::from(dir)
        });
        let key_dir = opt.key_dir.unwrap_or_else(|| {
            let dir: String = settings.get("directories.key_dir").expect("Missing directories.key_dir in configuration");
            PathBuf::from(dir)
        });


        let cgroup_memory = opt.cgroup_memory.unwrap_or_else(|| {
            let dir: String = settings.get("cgroups.memory")
                .expect("Missing cgroups.memory in configuration");
            PathBuf::from(dir)
        });

        let cgroup_cpu = opt.cgroup_cpu.unwrap_or_else(|| {
            let dir: String = settings.get("cgroups.cpu")
                .expect("Missing cgroup.cpu in configuration");
            PathBuf::from(dir)
        });


        let unshare_root = opt.unshare_root.unwrap_or_else(|| {
            let dir: String = settings.get("devices.unshare_root")
                .expect("Missing devices.unshare_root in configuration");
            PathBuf::from(dir)
        });

        let unshare_fstype = opt.unshare_fstype.unwrap_or_else(|| {
            settings.get("devices.unshare_fstype")
                .expect("Missing unshare_fstype in configuration")
        });

        let device_mapper = opt.device_mapper.unwrap_or_else(|| {
            let dm: String = settings.get("devices.device_mapper")
                .expect("Missing devices.device_mapper in configuration");
            PathBuf::from(dm)
        });

        let device_mapper_dev = opt.device_mapper_dev.unwrap_or_else(|| {
            settings.get("devices.device_mapper_dev")
                .expect("Missing devices.device_mapper_dev in configuration")
        });

        let loop_control = opt.loop_control.unwrap_or_else(|| {
            let lc: String = settings.get("devices.loop_control")
                .expect("Missing devices.loop_control in configuration");
            PathBuf::from(lc)
        });

        let loop_dev = opt.loop_dev.unwrap_or_else(|| {
            settings.get("devices.loop_dev")
                .expect("Missing devices.loop_dev in configuration")
        });

        Settings {
            debug,
            directories: Directories {
                container_dirs,
                run_dir,
                data_dir,
                key_dir,
            },
            console_address,
            global_data_dir,
            cgroups: CGroups {
                memory: cgroup_memory,
                cpu: cgroup_cpu,
            },
            devices: Devices {
                unshare_root,
                unshare_fstype,
                device_mapper,
                device_mapper_dev,
                loop_control,
                loop_dev,
            }
        }
    };
}

#[derive(Debug, StructOpt)]
#[structopt(name = "north", about = "North")]
struct CliOptions {
    /// File that contains the north configuration
    #[structopt(short, long)]
    pub config: Option<String>,

    #[structopt(short, long)]
    /// Print debug logs
    pub debug: bool,

    /// Directory containing images in container format
    #[structopt(long)]
    pub container_dir: Option<Vec<PathBuf>>,

    /// Directory with unpacked containers
    #[structopt(long)]
    pub run_dir: Option<PathBuf>,

    /// Directory where rw data of container shall be stored
    #[structopt(long)]
    pub data_dir: Option<PathBuf>,

    /// Directory where public signing keys are stored
    #[structopt(long)]
    pub key_dir: Option<PathBuf>,

    /// Console address
    #[structopt(long)]
    pub console_address: Option<String>,

    /// Share the rw data location between containers. Do not setup
    /// a dedicated data dir per container.
    #[structopt(long)]
    pub global_data_dir: bool,

    /// Parent mountpoint of north path. North needs to set private mount propagation
    /// on the parent mount of the north runtime dir. This mountpoint varies
    #[structopt(long)]
    pub unshare_root: Option<PathBuf>,

    /// File system of the fs mounted on unshare_root
    #[structopt(long)]
    pub unshare_fstype: Option<String>,

    /// CGroups Memory dir. This can be a subdir of the root memory cgroup.
    /// The directory is created if it does not exist.
    /// This groups acts as the toplevel north memory cgroup.
    #[structopt(long)]
    pub cgroup_memory: Option<PathBuf>,

    /// CGroups CPU dir. This can be a subdir of the root memory cgroup.
    /// The directory is created if it does not exist.
    /// This groups acts as the toplevel north cpu cgroup.
    #[structopt(long)]
    pub cgroup_cpu: Option<PathBuf>,

    /// Device mapper control file e.g /dev/mapper/control
    #[structopt(long)]
    pub device_mapper: Option<PathBuf>,

    /// Device mapper dev prefix e.g /dev/mapper/dm-
    #[structopt(long)]
    pub device_mapper_dev: Option<String>,

    /// Loopback control file e.g /dev/loop-control
    #[structopt(long)]
    pub loop_control: Option<PathBuf>,

    /// Loopback device files e.g /dev/loop or /dev/block/loop
    #[structopt(long)]
    pub loop_dev: Option<String>,
}

#[derive(Debug)]
pub struct Directories {
    pub container_dirs: Vec<PathBuf>,
    pub run_dir: PathBuf,
    pub data_dir: PathBuf,
    pub key_dir: PathBuf,
}

#[derive(Debug)]
pub struct CGroups {
    pub memory: PathBuf,
    pub cpu: PathBuf,
}

#[derive(Debug)]
pub struct Devices {
    pub unshare_root: PathBuf,
    pub unshare_fstype: String,
    pub device_mapper: PathBuf,
    pub device_mapper_dev: String,
    pub loop_control: PathBuf,
    pub loop_dev: String,
}

#[derive(Debug)]
pub struct Settings {
    pub debug: bool,
    pub console_address: String,
    pub global_data_dir: bool,
    pub directories: Directories,
    pub cgroups: CGroups,
    pub devices: Devices,
}

impl fmt::Display for Settings {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{:#?}", self)
    }
}
