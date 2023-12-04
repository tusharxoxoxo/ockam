use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json as json;

use ockam::identity::utils::now;
use ockam::identity::{AttributesEntry, Identifier};
use ockam_core::compat::{collections::HashMap, string::String};
use ockam_core::errcode::{Kind, Origin};
use ockam_core::Result;

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct PreTrustedIdentities(pub HashMap<Identifier, AttributesEntry>);

impl PreTrustedIdentities {
    pub fn new_from_disk(path: PathBuf) -> Result<Self> {
        Ok(PreTrustedIdentities(Self::parse_from_disk(&path)?))
    }

    pub fn new_from_string(entries: &str) -> Result<Self> {
        Ok(Self::new_from_hashmap(Self::parse(entries)?))
    }

    pub fn new_from_hashmap(entries: HashMap<Identifier, AttributesEntry>) -> Self {
        PreTrustedIdentities(entries)
    }

    fn parse_from_disk(path: &PathBuf) -> Result<HashMap<Identifier, AttributesEntry>> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| ockam_core::Error::new(Origin::Other, Kind::Io, e))?;
        Self::parse(&contents)
    }

    fn parse(entries: &str) -> Result<HashMap<Identifier, AttributesEntry>> {
        let raw_map = json::from_str::<HashMap<Identifier, HashMap<String, String>>>(entries)
            .map_err(|e| ockam_core::Error::new(Origin::Other, Kind::Invalid, e))?;
        let now = now()?;
        Ok(raw_map
            .into_iter()
            .map(|(identity_id, raw_attrs)| {
                let attrs = raw_attrs
                    .into_iter()
                    .map(|(k, v)| (k.as_bytes().to_vec(), v.as_bytes().to_vec()))
                    .collect();
                (identity_id, AttributesEntry::new(attrs, now, None, None))
            })
            .collect())
    }
}

impl From<HashMap<Identifier, AttributesEntry>> for PreTrustedIdentities {
    fn from(h: HashMap<Identifier, AttributesEntry>) -> PreTrustedIdentities {
        PreTrustedIdentities(h)
    }
}
