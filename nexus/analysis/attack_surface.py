"""Canonical attack-surface inventory built from authorized observations."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


def _key(value: str) -> str:
    return value.strip().lower()


@dataclass(frozen=True)
class Service:
    protocol: str
    port: int
    name: str = ""
    product: str = ""
    version: str = ""
    exposure: str = "unknown"


@dataclass(frozen=True)
class Asset:
    asset_id: str
    hostname: str = ""
    addresses: tuple[str, ...] = ()
    services: tuple[Service, ...] = ()
    technologies: tuple[str, ...] = ()
    identities: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()


class AttackSurface:
    """Deterministic inventory that merges observations without guessing."""

    def __init__(self) -> None:
        self._assets: dict[str, Asset] = {}

    @property
    def assets(self) -> tuple[Asset, ...]:
        return tuple(self._assets.values())

    def add(self, asset: Asset) -> Asset:
        if not asset.asset_id.strip():
            raise ValueError("asset_id must not be empty")
        existing = self._assets.get(_key(asset.asset_id))
        if existing is None:
            self._assets[_key(asset.asset_id)] = asset
            return asset
        merged = Asset(
            asset_id=existing.asset_id,
            hostname=existing.hostname or asset.hostname,
            addresses=tuple(dict.fromkeys(existing.addresses + asset.addresses)),
            services=tuple(dict.fromkeys(existing.services + asset.services)),
            technologies=tuple(dict.fromkeys(existing.technologies + asset.technologies)),
            identities=tuple(dict.fromkeys(existing.identities + asset.identities)),
            tags=tuple(dict.fromkeys(existing.tags + asset.tags)),
        )
        self._assets[_key(asset.asset_id)] = merged
        return merged

    def add_many(self, assets: Iterable[Asset]) -> None:
        for asset in assets:
            self.add(asset)

    def get(self, asset_id: str) -> Asset | None:
        return self._assets.get(_key(asset_id))

    def exposed_services(self) -> tuple[tuple[str, Service], ...]:
        rows: list[tuple[str, Service]] = []
        for asset in self.assets:
            for service in asset.services:
                if service.exposure == "external":
                    rows.append((asset.asset_id, service))
        return tuple(rows)

    def to_dict(self) -> dict[str, list[dict[str, object]]]:
        return {
            "assets": [
                {
                    "asset_id": asset.asset_id,
                    "hostname": asset.hostname,
                    "addresses": list(asset.addresses),
                    "services": [service.__dict__ for service in asset.services],
                    "technologies": list(asset.technologies),
                    "identities": list(asset.identities),
                    "tags": list(asset.tags),
                }
                for asset in self.assets
            ]
        }
