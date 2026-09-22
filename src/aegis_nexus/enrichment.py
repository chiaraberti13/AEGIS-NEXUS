from __future__ import annotations

import ipaddress
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import geoip2.database
from geoip2.errors import AddressNotFoundError


class LocalGeoIPEnricher:
    """Offline GeoIP/ASN enrichment using operator-supplied MaxMind databases."""

    def __init__(
        self,
        city_db: str | None = None,
        asn_db: str | None = None,
        *,
        city_reader: Any | None = None,
        asn_reader: Any | None = None,
    ):
        self.city_path = Path(city_db).expanduser() if city_db else None
        self.asn_path = Path(asn_db).expanduser() if asn_db else None
        self.city_reader = city_reader
        self.asn_reader = asn_reader
        self.city_error: str | None = None
        self.asn_error: str | None = None

        if self.city_reader is None and self.city_path:
            try:
                self.city_reader = geoip2.database.Reader(str(self.city_path))
            except (OSError, ValueError) as exc:
                self.city_error = type(exc).__name__

        if self.asn_reader is None and self.asn_path:
            try:
                self.asn_reader = geoip2.database.Reader(str(self.asn_path))
            except (OSError, ValueError) as exc:
                self.asn_error = type(exc).__name__

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _eligible(value: Any) -> str | None:
        if not value:
            return None
        try:
            ip = ipaddress.ip_address(str(value))
        except ValueError:
            return None
        if not ip.is_global:
            return None
        return str(ip)

    @staticmethod
    def _source(path: Path | None, kind: str) -> str:
        name = path.name if path else kind
        return f"maxmind-local:{name}"[:256]

    def status(self) -> dict[str, Any]:
        return {
            "mode": "local_offline",
            "network_requests": False,
            "configured": bool(self.city_path or self.asn_path or self.city_reader or self.asn_reader),
            "city": {
                "configured": bool(self.city_path or self.city_reader),
                "ready": self.city_reader is not None,
                "database": self.city_path.name if self.city_path else None,
                "error": self.city_error,
            },
            "asn": {
                "configured": bool(self.asn_path or self.asn_reader),
                "ready": self.asn_reader is not None,
                "database": self.asn_path.name if self.asn_path else None,
                "error": self.asn_error,
            },
        }

    def enrich(self, event: dict[str, Any]) -> dict[str, Any]:
        ip = self._eligible((event.get("observed") or {}).get("source_ip"))
        if not ip:
            return event

        result = deepcopy(event)
        enrichment = result.setdefault("enrichment", {})
        observed_at = self._now()

        if self.city_reader is not None and "geo" not in enrichment:
            try:
                response = self.city_reader.city(ip)
            except AddressNotFoundError:
                response = None
            except Exception:
                response = None
            if response is not None:
                data: dict[str, Any] = {}
                country = getattr(getattr(response, "country", None), "iso_code", None)
                city = getattr(getattr(response, "city", None), "name", None)
                location = getattr(response, "location", None)
                latitude = getattr(location, "latitude", None)
                longitude = getattr(location, "longitude", None)
                accuracy_radius = getattr(location, "accuracy_radius", None)
                timezone_name = getattr(location, "time_zone", None)
                if country:
                    data["country"] = str(country)[:8]
                if city:
                    data["city"] = str(city)[:256]
                if latitude is not None:
                    data["latitude"] = float(latitude)
                if longitude is not None:
                    data["longitude"] = float(longitude)
                if accuracy_radius is not None:
                    data["accuracy_radius_km"] = int(accuracy_radius)
                if timezone_name:
                    data["time_zone"] = str(timezone_name)[:128]
                if data:
                    enrichment["geo"] = {
                        "source": self._source(self.city_path, "city"),
                        "observed_at": observed_at,
                        "data": data,
                    }

        if self.asn_reader is not None and "asn" not in enrichment:
            try:
                response = self.asn_reader.asn(ip)
            except AddressNotFoundError:
                response = None
            except Exception:
                response = None
            if response is not None:
                number = getattr(response, "autonomous_system_number", None)
                organization = getattr(response, "autonomous_system_organization", None)
                data: dict[str, Any] = {}
                if number is not None:
                    data["asn"] = f"AS{int(number)}"
                    data["asn_number"] = int(number)
                if organization:
                    data["organization"] = str(organization)[:512]
                if data:
                    enrichment["asn"] = {
                        "source": self._source(self.asn_path, "asn"),
                        "observed_at": observed_at,
                        "data": data,
                    }

        return result

    def close(self) -> None:
        seen: set[int] = set()
        for reader in (self.city_reader, self.asn_reader):
            if reader is None or id(reader) in seen:
                continue
            seen.add(id(reader))
            close = getattr(reader, "close", None)
            if callable(close):
                close()
