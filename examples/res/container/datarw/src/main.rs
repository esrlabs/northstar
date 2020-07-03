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

use log::debug;
use std::{
    convert::Into,
    env, fs, io,
    io::{Read, Write},
    path::PathBuf,
    thread, time,
};

const DATA: &str = "DATA";

fn main() -> io::Result<()> {
    logd_logger::builder()
        .parse_filters("datarw")
        .tag("datarw")
        .init();

    let sleep = |s| {
        thread::sleep(time::Duration::from_secs(s));
    };

    let data = PathBuf::from(std::env::var(DATA).expect("Cannot read env var DATA"));

    debug!("Doing some operations on {}", data.display());

    debug!("Listing {}", data.display());
    for e in fs::read_dir(&data)? {
        let e = e?;
        debug!(
            "{}: {:?}",
            e.path().display(),
            e.path().metadata()?.file_type()
        );
    }

    let file = data.join("foo");

    debug!("Trying to create {}", file.display());
    let mut f = loop {
        match fs::File::create(&file) {
            Ok(f) => {
                debug!("Success!");
                break f;
            }
            Err(e) => ("Failed: {}", e),
        };
        sleep(1);
    };

    f.write_all(b"hello")?;
    f.flush()?;
    drop(f);

    let we = (
        env::args().take(2).map(Into::into).collect::<Vec<String>>(),
        env::vars()
            .take(2)
            .map(|(k, v)| format!("{}: {}", k, v))
            .collect::<Vec<String>>(),
    );

    loop {
        let mut f = fs::File::create(&file)?;
        let now = serde_json::to_string_pretty(&we)?;
        debug!("Creating {} with context {}", file.display(), now);
        f.write_all(now.as_bytes())?;

        debug!("Listing {}", data.display());
        for e in fs::read_dir(&data)? {
            let e = e?;
            debug!(
                "{}: {:?}",
                e.path().display(),
                e.path().metadata()?.file_type()
            );
        }

        let mut f = fs::File::open(&file)?;
        let mut buffer = String::new();
        f.read_to_string(&mut buffer)?;
        debug!("Content of {}: {}", file.display(), buffer);

        debug!("Unlinking {}", file.display());
        fs::remove_file(&file)?;

        sleep(1);
    }
}
