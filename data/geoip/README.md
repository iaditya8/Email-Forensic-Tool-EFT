# MaxMind GeoLite2 Offline Database Directory

Place your downloaded `.mmdb` database files directly into this directory:

- **`GeoLite2-City.mmdb`** (Provides City, Country, Region, Latitude & Longitude)
- **`GeoLite2-ASN.mmdb`** (Provides Autonomous System Number & Organization Name)

---

## How to Get Free MaxMind GeoLite2 Databases
1. Sign up for a free account at [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).
2. Download `GeoLite2-City.tar.gz` and `GeoLite2-ASN.tar.gz`.
3. Extract the `.mmdb` files and paste them into this folder (`data/geoip/`).

---

## Environment Variables
EFT automatically detects databases placed in `data/geoip/`. You can also configure explicit paths via `.env`:

```env
GEOIP_CITY_DB="data/geoip/GeoLite2-City.mmdb"
GEOIP_ASN_DB="data/geoip/GeoLite2-ASN.mmdb"
```

## Air-Gapped Forensic Guarantee
EFT operates entirely offline with **zero outbound network requests** when querying these local MMDB databases.
