//! GeoIP lookups backed by a MaxMind database.
//!
//! When a block configures `geoip_db`, the request pipeline resolves the
//! connecting client's address to country/city/continent and stamps the result
//! into `x-geoip-*` headers for upstreams. Lookups go through the `maxminddb`
//! crate; the database (a `.mmdb` file such as GeoLite2-City) is memory-mapped
//! once at startup and shared by `Arc`, so per-request lookups are allocation-
//! light and lock-free.

use anyhow::{Context, Result};
use maxminddb::path;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

/// A loaded MaxMind database ready for repeated lookups.
///
/// Cheap to [`Clone`] via the inner `Arc`; construct one per configured
/// database and share it across the request pipeline.
pub struct GeoIpService {
    reader: Arc<maxminddb::Reader<Vec<u8>>>,
}

impl GeoIpService {
    /// Open and load the MaxMind database at `db_path`.
    ///
    /// The whole file is read into memory once.
    ///
    /// # Errors
    ///
    /// Returns an error if the file does not exist or cannot be parsed as a
    /// MaxMind database.
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

    /// Resolve `ip` to its geolocation, or `None` when the address is absent
    /// from the database (e.g. a private or unallocated address). Every
    /// individual field is independently optional, since not all database
    /// tiers carry city-level data.
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

/// Geolocation fields resolved for an address. Each is independently optional
/// depending on database coverage.
#[derive(Debug, Clone)]
pub struct GeoIpInfo {
    /// English country name (e.g. `"United States"`).
    pub country: Option<String>,
    /// English city name.
    pub city: Option<String>,
    /// English continent name (e.g. `"North America"`).
    pub continent: Option<String>,
    /// ISO 3166-1 alpha-2 country code (e.g. `"US"`).
    pub iso_code: Option<String>,
}
