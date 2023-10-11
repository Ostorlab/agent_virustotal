"""VirusTotal agent implementation : Agent responsible for scanning a file through the Virus Total DB."""
import ipaddress
import logging
from typing import Any

import magic
from ostorlab.agent import agent, definitions as agent_definitions
from ostorlab.agent.kb import kb
from ostorlab.agent.message import message as msg
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.runtimes import definitions as runtime_definitions

from agent import file
from agent import process_scans
from agent import virustotal

logger = logging.getLogger(__name__)


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
        self.api_key = self.args.get("api_key")
        self.whitelist_types = self.args.get("whitelist_types", [])

    def process(self, message: msg.Message) -> None:
        """Process message of type v3.asset.file. Scan the file content through the Virus Total public API, assign a
         risk rating, a technical report and emits a message of type v3.report.vulnerability .

        Args:
            message: Message containing the file to scan.

        Raises:
            VirusTotalApiError: In case the Virus Total api encountered problems.
            NameError: In case the scans were not defined.
        """
        file_content = file.get_file_content(message)
        if file_content is not None:
            if (
                self.whitelist_types is not None
                and len(self.whitelist_types) != 0
                and magic.from_buffer(file_content, mime=True)
                not in self.whitelist_types
            ):
                return None
            response = virustotal.scan_file_from_message(
                file_content=file_content, api_key=self.api_key
            )
            self._process_response(response, message.data.get("path"))
        else:
            targets = self._prepare_targets(message)
            for target in targets:
                response = virustotal.scan_url_from_message(target, self.api_key)
                self._process_response(response, target)

    def _process_response(self, response: dict[str, Any], target: str | None) -> None:
        try:
            scans = virustotal.get_scans(response)
        except virustotal.VirusTotalApiError:
            logger.error("Virus Total API encountered some problems. Please try again.")
            return None

        try:
            if scans is not None:
                technical_detail = process_scans.get_technical_details(scans, target)
                risk_rating = process_scans.get_risk_rating(scans)
                self.report_vulnerability(
                    entry=kb.KB.VIRUSTOTAL_SCAN,
                    technical_detail=technical_detail,
                    risk_rating=risk_rating,
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
            if message.data.get("mask") is None:
                ip_network = ipaddress.ip_network(host)
            else:
                mask = message.data.get("mask")
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
