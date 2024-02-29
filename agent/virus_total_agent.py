"""VirusTotal agent implementation : Agent responsible for scanning a file through the Virus Total DB."""

import hashlib
import ipaddress
import logging
from typing import Any
from typing import cast

import magic
from ostorlab.agent import agent, definitions as agent_definitions
from ostorlab.agent.kb import kb
from ostorlab.agent.message import message as msg
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.runtimes import definitions as runtime_definitions
from rich import logging as rich_logging

from agent import file
from agent import process_scans
from agent import virustotal

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)

logger = logging.getLogger(__name__)

IPV4_CIDR_LIMIT = 16
IPV6_CIDR_LIMIT = 112


class VirusTotalAgent(
    agent.Agent, agent_report_vulnerability_mixin.AgentReportVulnMixin
):
    """Agent responsible for scanning a file through the Virus Total DB."""

    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:
        """Init method.
        Args:
            agent_definition: Attributes of the agent.
            agent_settings: Settings of running instance of the agent.
        """
        super().__init__(agent_definition, agent_settings)
        api_key = self.args.get("api_key")
        if api_key is None:
            raise ValueError("Virustotal API Key is not set")
        else:
            self.api_key = cast(str, api_key)
        self.whitelist_types = self.args.get("whitelist_types") or []

    def process(self, message: msg.Message) -> None:
        """Process message of type v3.asset.file. Scan the file content through the Virus Total public API, assign a
         risk rating, a technical report and emits a message of type v3.report.vulnerability .

        Args:
            message: Message containing the file to scan.

        Raises:
            NameError: In case the scans were not defined.
        """
        file_content = file.get_file_content(message)
        if file_content is not None:
            if (
                len(self.whitelist_types) != 0
                and magic.from_buffer(file_content, mime=True)
                not in self.whitelist_types
            ):
                return None
            response = virustotal.scan_file_from_message(
                file_content=file_content, api_key=self.api_key
            )
            target = message.data.get("path") or hashlib.md5(file_content).hexdigest()
            self._process_response(response, target)
        else:
            targets = self._prepare_targets(message)
            for target in targets:
                response = virustotal.scan_url_from_message(target, self.api_key)
                self._process_response(response, target)

    def _process_response(self, response: dict[str, Any], target: str | None) -> None:
        scans = virustotal.get_scans(response)
        try:
            if scans is not None:
                (
                    secure_scan_report,
                    vulnerable_scan_report,
                ) = process_scans.split_scans_by_result(scans)

                if len(secure_scan_report) > 0:
                    technical_detail = process_scans.get_technical_details(
                        secure_scan_report, target
                    )
                    self.report_vulnerability(
                        entry=kb.KB.SECURE_VIRUSTOTAL_SCAN,
                        technical_detail=technical_detail,
                        risk_rating=agent_report_vulnerability_mixin.RiskRating.SECURE,
                    )

                if len(vulnerable_scan_report) > 0:
                    technical_detail = process_scans.get_technical_details(
                        vulnerable_scan_report, target
                    )
                    self.report_vulnerability(
                        entry=kb.KB.INSECURE_VIRUSTOTAL_SCAN,
                        technical_detail=technical_detail,
                        risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH,
                    )

        except NameError:
            logger.error("The scans list is empty.")

    def _get_schema(self, message: msg.Message) -> str:
        """Returns the schema to be used for the target."""
        if message.data.get("schema") is not None:
            return str(message.data["schema"])
        elif message.data.get("protocol") is not None:
            return str(message.data["protocol"])
        elif self.args.get("https") is True:
            return "https"
        else:
            return "http"

    def _prepare_targets(self, message: msg.Message) -> list[str]:
        """Prepare targets based on type, if a domain name is provided, port and protocol are collected
        from the config."""
        if message.data.get("host") is not None:
            host = str(message.data.get("host"))
            mask = message.data.get("mask")
            if mask is None:
                ip_network = ipaddress.ip_network(host)
            else:
                version = message.data.get("version")
                if version not in (4, 6):
                    raise ValueError(f"Incorrect ip version {version}.")
                elif version == 4 and int(mask) < IPV4_CIDR_LIMIT:
                    raise ValueError(
                        f"Subnet mask below {IPV4_CIDR_LIMIT} is not supported."
                    )
                elif version == 6 and int(mask) < IPV6_CIDR_LIMIT:
                    raise ValueError(
                        f"Subnet mask below {IPV6_CIDR_LIMIT} is not supported."
                    )
                ip_network = ipaddress.ip_network(f"{host}/{mask}", strict=False)
            return [str(h) for h in ip_network.hosts()]

        elif (domain_name := message.data.get("name")) is not None:
            schema = self._get_schema(message)
            port = self.args.get("port")
            if schema == "https" and port not in [443, None]:
                url = f"https://{domain_name}:{port}"
            elif schema == "https":
                url = f"https://{domain_name}"
            elif port == 80:
                url = f"http://{domain_name}"
            elif port is None:
                url = f"{schema}://{domain_name}"
            else:
                url = f"{schema}://{domain_name}:{port}"

            return [url]

        elif (url_temp := message.data.get("url")) is not None:
            return [url_temp]
        else:
            return []


if __name__ == "__main__":
    logger.debug("Virus total starting..")
    VirusTotalAgent.main()
