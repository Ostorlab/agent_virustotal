"""VirusTotal agent implementation : Agent responsible for scanning a file through the Virus Total DB."""
import logging

from ostorlab.agent import agent, definitions as agent_definitions
from ostorlab.agent.kb import kb
from ostorlab.agent.message import message as msg
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.runtimes import definitions as runtime_definitions

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

    def process(self, message: msg.Message) -> None:
        """Process message of type v3.asset.file. Scan the file content through the Virus Total public API, assign a
         risk rating, a technical report and emits a message of type v3.report.vulnerability .

        Args:
            message: Message containing the file to scan.

        Raises:
            VirusTotalApiError: In case the Virus Total api encountered problems.
            NameError: In case the scans were not defined.
        """
        if message.data.get("content") is not None:
            response = virustotal.scan_file_from_message(message, self.api_key)
        elif message.data.get("url") is not None:
            response = virustotal.scan_url_from_message(message, self.api_key)
        else:
            return None

        try:
            scans = virustotal.get_scans(response)
        except virustotal.VirusTotalApiError:
            logger.error("Virus Total API encountered some problems. Please try again.")
            raise

        try:
            technical_detail = process_scans.get_technical_details(scans)
            risk_rating = process_scans.get_risk_rating(scans)
            self.report_vulnerability(
                entry=kb.KB.VIRUSTOTAL_SCAN,
                technical_detail=technical_detail,
                risk_rating=risk_rating,
            )
        except NameError:
            logger.error("The scans list is empty.")
            raise


if __name__ == "__main__":
    logger.debug("Virus total starting..")
    VirusTotalAgent.main()
