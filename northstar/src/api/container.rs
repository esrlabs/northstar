// Copyright (c) 2021 ESRLabs
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

use npk::manifest::{Name, Version};
use serde::{Deserialize, Serialize};
use std::{
    convert::TryFrom,
    fmt::{self, Display},
    sync::Arc,
};

#[derive(Clone, Eq, PartialOrd, PartialEq, Debug, Hash, Serialize, Deserialize)]
pub struct Container {
    #[serde(flatten)]
    inner: Arc<Inner>,
}

impl Container {
    pub fn new(name: Name, version: Version) -> Container {
        Container {
            inner: Arc::new(Inner { name, version }),
        }
    }

    /// Container name
    pub fn name(&self) -> &Name {
        &self.inner.name
    }

    /// Container version
    pub fn version(&self) -> &Version {
        &self.inner.version
    }
}

impl TryFrom<&str> for Container {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut split = value.split(':');
        let name = split.next().ok_or("Missing container name")?;
        let version = split.next().ok_or("Missing container version")?;
        let version = Version::parse(&version).map_err(|_| "Invalid version")?;
        Ok(Container::new(name.into(), version))
    }
}

impl Display for Container {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.inner.name, self.inner.version,)
    }
}

#[derive(Eq, PartialOrd, PartialEq, Debug, Hash, Serialize, Deserialize)]
struct Inner {
    name: Name,
    version: Version,
}
