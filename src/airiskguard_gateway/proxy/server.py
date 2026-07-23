from __future__ import annotations

import asyncio
import logging

from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from airiskguard_gateway.audit.logger import AuditLogger
from airiskguard_gateway.audit.shipper import AuditShipper
from airiskguard_gateway.config import GatewayConfig
from airiskguard_gateway.policy.engine import PolicyEngine
from airiskguard_gateway.policy.syncer import PolicySyncer
from airiskguard_gateway.proxy.addon import AIRiskGuardAddon
from airiskguard_gateway.proxy.cert import CertManager
from airiskguard_gateway.routing.engine import RoutingEngine
from airiskguard_gateway.scanner.engine import ScanEngine

log = logging.getLogger(__name__)


async def run_proxy(config: GatewayConfig) -> None:
    cert_manager = CertManager()
    cert_dir = cert_manager.ensure_cert()

    logger = AuditLogger(config)
    scanner = ScanEngine(config)
    policy = PolicyEngine(config)
    router = RoutingEngine(
        rules=config.routing.parsed_rules(),
        destinations=config.routing.parsed_destinations(),
    )
    addon = AIRiskGuardAddon(config, logger, scanner, policy, router)
    shipper = AuditShipper(config, logger)
    syncer = PolicySyncer(config, policy)

    opts = Options(
        listen_host=config.listen_host,
        listen_port=config.listen_port,
        ssl_insecure=False,
        confdir=str(cert_dir),
    )

    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    master.addons.add(addon)

    shipper_task = asyncio.create_task(shipper.run())
    syncer_task = asyncio.create_task(syncer.run())

    log.info("AIRiskGuard Gateway listening on %s:%d", config.listen_host, config.listen_port)

    try:
        await master.run()
    finally:
        shipper.stop()
        syncer.stop()
        shipper_task.cancel()
        syncer_task.cancel()
