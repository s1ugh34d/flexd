use anyhow::{Context, Result};
use maxminddb::path;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

pub struct GeoIpService {
    reader: Arc<maxminddb::Reader<Vec<u8>>>,
}

impl GeoIpService {
    pub fn new(db_path: &str) -> Result<Self> {
        let path = Path::new(db_path);
        if !path.exists() {
            anyhow::bail!("GeoIP database not found: {}", db_path);
        }

        let reader = maxminddb::Reader::open_readfile(path)
            .with_context(|| format!("Failed to open GeoIP database: {}", db_path))?;

        Ok(Self {
            reader: Arc::new(reader),
        })
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<GeoIpInfo> {
        let lookup = self.reader.lookup(ip).ok()?;
        if !lookup.has_data() {
            return None;
        }

        let country_iso: Option<String> = lookup.decode_path(&path!["country", "iso_code"]).ok().flatten();
        let country_name: Option<String> = lookup.decode_path(&path!["country", "names", "en"]).ok().flatten();
        let city_name: Option<String> = lookup.decode_path(&path!["city", "names", "en"]).ok().flatten();
        let continent_name: Option<String> = lookup.decode_path(&path!["continent", "names", "en"]).ok().flatten();

        Some(GeoIpInfo {
            country: country_name,
            city: city_name,
            continent: continent_name,
            iso_code: country_iso,
        })
    }
}

#[derive(Debug, Clone)]
pub struct GeoIpInfo {
    pub country: Option<String>,
    pub city: Option<String>,
    pub continent: Option<String>,
    pub iso_code: Option<String>,
}
