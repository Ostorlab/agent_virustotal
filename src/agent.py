"""VirusTotal agent implementation : Agent responsible for scanning a file through the Virus Total DB."""
import logging
from typing import Dict

from ostorlab.agent import agent
from ostorlab.agent import message as msg
from . import markdown
from . import virustotal


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
        """Overriden message processing method."""
        response = virustotal.scan_file(message, self.api_key)

        try:
            scans = virustotal.get_scans(response)
        except virustotal.VirusTotalApiError as e:
            logger.error('Virus Total API encountered some problems. Please try again.')
            raise e

        if scans:
            risk_rating = self._get_risk_rating(scans)
            technical_detail = self._get_technical_details(scans)
            title = 'VirusTotal report'
            self.emit(
                'v3.report.event.vulnerability',
                {
                    'title': title,
                    'technical_detail': technical_detail,
                    'risk_rating': risk_rating
                }
            )

    def _get_risk_rating(self, scans:Dict) -> str:
        """Method responsible for assigning a risk level to the scanned file.
        Returns:
            'HIGH' if at least one anti-virus detected the file as a virus, else Secure.
        """
        for scanner_result in scans.values():
            if scanner_result['detected']:
                return 'HIGH'
        return 'SECURE'

    def _get_technical_details(self, scans:Dict) -> str:
        """Method that returns a markdwon table of the Virus Total scan.
        Each row presents an antivirus with corresponding scan result : Malicious/Safe.
        Args:
            scans : Dictionary of the scans.
        Returns:
            technical_detail : Markdown table of the scans results.
        """
        scans = markdown.prepare_data_for_markdown_formatting(scans)
        technical_detail = markdown.table_markdown(scans)
        return technical_detail
