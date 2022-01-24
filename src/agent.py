"""VirusTotal agent implementation : Agent responsible for scanning a file through the Virus Total DB."""
import logging

from ostorlab.agent import agent
from ostorlab.agent import message as msg
from ostorlab.agent.kb import kb

from . import virustotal
from . import process_scans


logger = logging.getLogger(__name__)

class VirusTotalAgent(agent.Agent):
    """Agent responsible for scanning a file through the Virus Total DB."""

    def __init__(self, agent_def, agent_settings) -> None:
        """Init method.
        Args:
            agent_def: Attributes of the agent.
            agent_settings: Settings of running instance of the agent.
        """
        super().__init__(agent_def, agent_settings)
        self.api_key = self.args.get('api_key')

    def process(self, message: msg.Message) -> None:
        """Process message of type v3.asset.file;
        scan the file content throught the Virus Total public API,
        assign a risk rating, a technical report
        and emits a message of type v3.report.vulnerability .
        Args:
            message: Message containing the file to scan.
        Raises:
            VirusTotalApiError: In case the Virus Total api encountered problems.
            NameError: In case the scans were not defined.
        """
        response = virustotal.scan_file_from_message(message, self.api_key)

        try:
            scans = virustotal.get_scans(response)
        except virustotal.VirusTotalApiError as e:
            logger.error('Virus Total API encountered some problems. Please try again.')
            raise e

        try:
            risk_rating = process_scans.get_risk_rating(scans)
            technical_detail = process_scans.get_technical_details(scans)
            title = kb.Kb.VIRUSTOTAL_SCAN
            self.emit(
                'v3.report.vulnerability',
                {
                    'title': title,
                    'technical_detail': technical_detail,
                    'risk_rating': risk_rating
                }
            )
        except NameError() as e:
            logger.error('The scans list is empty.')
            raise e
