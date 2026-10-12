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
    make_target: str
    kaslr_pc_offsets: tuple[int, ...]
    product_models: tuple[str, ...] = ()
    stack_route: str = "sendmmsg"
    memstart_strategy: str = "bugreport"
    bundled_simpleperf: bool = False
    route_delay_usec: int = 50_000
    proc_uid_sentinel: str = "run_as"
    kgsl_reclaim: bool = False
    mm_recycle_slabs: int = 0
    reclaim_pairs: int = 64
    reclaim_sends: int = 64
    audio_java_fallback: bool = False
    audio_installer_credentials: bool = False
    device_owner_system_credentials: bool = False
    ota_installer_credentials: bool = False
    meta_accounts_system_credentials: bool = False
    shell_root_package_actions: bool = False
    presence_installer_credentials: bool = False
    presence_runtime_keys: tuple[str, ...] = ()
    presence_full_sensor_width: float | None = None
    ota_packages: tuple[str, ...] = (
        "com.facebook.aloha.otaui",
        "com.facebook.aloha.alohaotasetup",
    )

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
        make_target="portal-terry-5051355900018050",
        kaslr_pc_offsets=(
            0x3D7E,
            0x3D54,
            0x153C,
            0x11756DC,
            0x1175724,
            0x363C6,
            0xAF90E,
            0x136E,
            0x3A72,
        ),
    ),
    PortalTarget(
        key="portal-plus-aloha-1041515800015050",
        model="Meta Portal+ (1st generation)",
        device="aloha",
        fingerprint=(
            "Facebook/aloha_prod/aloha:9/PKQ1.191202.001/"
            "1041515800015050:user/prod-keys"
        ),
        kernel="4.4.153+",
        preload_name="preload-portal-aloha-1041515800015050.so",
        make_target="portal-aloha-1041515800015050",
        kaslr_pc_offsets=(0x3354,),
        product_models=("Portal+",),
        stack_route="ptrace",
        bundled_simpleperf=True,
        route_delay_usec=0,
        proc_uid_sentinel="app",
        kgsl_reclaim=True,
        mm_recycle_slabs=20,
        reclaim_pairs=256,
        reclaim_sends=256,
        audio_java_fallback=True,
        audio_installer_credentials=True,
        device_owner_system_credentials=True,
        ota_installer_credentials=True,
        meta_accounts_system_credentials=True,
        shell_root_package_actions=True,
        presence_installer_credentials=True,
        presence_runtime_keys=(
            "enable_cv_background_detector_v2",
            "enable_hardware_cropping",
            "enable_liveness_metric",
        ),
        presence_full_sensor_width=4032.0,
        ota_packages=("com.facebook.aloha.otaui",),
    ),
)


def find_target(
    device: str, fingerprint: str, product_model: str | None = None
) -> PortalTarget | None:
    return next(
        (
            target
            for target in TARGETS
            if target.device == device and target.fingerprint == fingerprint
            and (
                not target.product_models
                or product_model is None
                or product_model in target.product_models
            )
        ),
        None,
    )
