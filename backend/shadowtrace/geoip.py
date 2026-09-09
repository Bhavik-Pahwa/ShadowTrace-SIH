from dataclasses import dataclass

from .config import ASN_DB, CITY_DB, REQUIRE_GEOIP


@dataclass
class GeoIPResult:
    country: str | None
    asn: str
    asn_description: str


class GeoIPEnricher:
    def __init__(self) -> None:
        self._city_reader = None
        self._asn_reader = None
        self.city_available = CITY_DB.exists()
        self.asn_available = ASN_DB.exists()
        if REQUIRE_GEOIP and (not self.city_available or not self.asn_available):
            missing = [str(path) for path, available in ((CITY_DB, self.city_available), (ASN_DB, self.asn_available)) if not available]
            raise FileNotFoundError(f"Required GeoIP database files are missing: {', '.join(missing)}")
        if self.city_available or self.asn_available:
            import geoip2.database

            try:
                if self.city_available:
                    self._city_reader = geoip2.database.Reader(str(CITY_DB))
                if self.asn_available:
                    self._asn_reader = geoip2.database.Reader(str(ASN_DB))
            except Exception:
                self.close()
                raise

    def enrich(self, ip: str, fallback_asn: str, fallback_description: str) -> GeoIPResult:
        country = None
        asn = fallback_asn
        description = fallback_description
        if self._city_reader:
            try:
                city = self._city_reader.city(ip)
                country = city.country.iso_code
            except Exception:
                country = None
        if self._asn_reader:
            try:
                asn_record = self._asn_reader.asn(ip)
                asn = f"AS{asn_record.autonomous_system_number}"
                description = asn_record.autonomous_system_organization or fallback_description
            except Exception:
                pass
        return GeoIPResult(country=country, asn=asn, asn_description=description)

    def close(self) -> None:
        for reader in (self._city_reader, self._asn_reader):
            if reader is not None:
                try:
                    reader.close()
                except Exception:
                    pass
