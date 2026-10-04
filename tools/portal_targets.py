"""Exact-build Portal targets supported by the host provisioner."""

from __future__ import annotations

from dataclasses import dataclass
import pathlib


@dataclass(frozen=True)
class PortalTarget:
    key: str
    model: str
    device: str
    fingerprint: str
    kernel: str
    preload_name: str
    make_target: str = "all"

    def preload_path(self, repository: pathlib.Path) -> pathlib.Path:
        return repository / "exploit" / "build" / self.preload_name


TARGETS = (
    PortalTarget(
        key="portal-go-terry-5051355900018050",
        model="Meta Portal Go",
        device="terry",
        fingerprint=(
            "Facebook/terry_prod/terry:10/QKQ1.210213.001/"
            "5051355900018050:user/prod-keys"
        ),
        kernel="4.9.227-perf+",
        preload_name="preload-portal-terry-5051355900018050.so",
    ),
)


def find_target(device: str, fingerprint: str) -> PortalTarget | None:
    return next(
        (
            target
            for target in TARGETS
            if target.device == device and target.fingerprint == fingerprint
        ),
        None,
    )
