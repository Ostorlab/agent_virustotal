"""VirusTotal agent implementation : Agent responsible for scanning a file through the Virus Total DB."""
import logging

from ostorlab.agent import agent
from ostorlab.agent import message as msg

from . import virustotal
from . import process_scans


logger = logging.getLogger(__name__)

class VirusTotalAgent(agent.Agent):
    """Agent responsible for scanning a file through the Virus Total DB."""

    def __init__(self, agent_def, agent_settings, api_key: str) -> None:
        """Init method.
        Args:
            agent_def: Attributes of the agent.
            agent_settings: Settings of running instance of the agent.
            api_key: Key for the Virus Total public API.
        """
        super().__init__(agent_def, agent_settings)
        self.api_key = api_key

    def process(self, message: msg.Message) -> None:
        """Process message of type v3.asset.file;
        scan the file content throught the Virus Total public API,
        assign a risk rating, a technical report
        and emits a message of type v3.report.vulnerability .
        """
        response = virustotal.scan_file(message, self.api_key)

        try:
            scans = virustotal.get_scans(response)
        except virustotal.VirusTotalApiError as e:
            logger.error('Virus Total API encountered some problems. Please try again.')
            raise e

        if scans:
            risk_rating = process_scans.get_risk_rating(scans)
            technical_detail = process_scans.get_technical_details(scans)
            title = 'VirusTotal report'
            self.emit(
                'v3.report.event.vulnerability',
                {
                    'title': title,
                    'technical_detail': technical_detail,
                    'risk_rating': risk_rating
                }
            )
