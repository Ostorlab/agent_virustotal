"""VirusTotal agent implementation : Agent responsible for scanning a file through the VirusTotal DB.
Usage :
trackerAgent = VirusTotalAgent(agent_def, agent_settings, api_key)
trackerAgent.run()
Please check the documentation for more details.
"""
import logging
import hashlib
from typing import Dict

from virus_total_apis import PublicApi as VirusTotalPublicApi

from ostorlab.agent import agent
from ostorlab.agent import message as agent_message
import utils


logger = logging.getLogger(__name__)


class OstorlabError(Exception):
    """Custom Error."""


class VirusTotalApiError(OstorlabError):
    """VirtualTotalApiError."""


class VirusTotalAgent(agent.Agent):
    """Agent responsible for scanning a file through the VirusTotal DB """

    def __init__(self, agent_def, agent_settings, api_key: str) -> None:
        """Init method.
        Args:
            api_key : Key for the virustotal api.
        """
        super().__init__(agent_def, agent_settings)
        self.api_key = api_key


    def _scan_file(self, message: agent_message.Message) -> Dict:
        """Method responsible for scanning a file through the virustotal api.
        Args:
            message: Message containing the file to scan.
        Returns:
            response: The response of the virustotal scan.
        """
        file_md5_hash = hashlib.md5(message.file)
        hash_hexa = file_md5_hash.hexdigest()
        virustotal_client = VirusTotalPublicApi(self.api_key)

        response = virustotal_client.get_file_report(hash_hexa)
        return response

    def _get_scans(self, response: Dict) -> Dict:
        """Method that returns the scans from the virus total api response.
        Args:
            response: Dictionary of the api response.
        Returns:
            scans: Dictionary of the scans.
        Raises:
            VirusTotalApiError: In case the API request encountered problems.
        """
        if 'results' not in response:
            raise VirusTotalApiError
        elif response['results']['response_code'] == 1:
            return response['results']['scans']
        else:
            return None

    def _get_risk_rating(self, scans:Dict) -> str:
        """Method responsible for assigning a risk level to the scanned file.
        Returns:
            'high' : if at least one anti-virus detected the file as a virus, else None.
        """
        for scanner_result in scans.values():
            if scanner_result['detected']:
                return 'high'
        return None

    def _get_technical_details(self, scans:Dict) -> str:
        """Method that returns a markdwon table of the virustotal scan.
        Each row presents an antivirus with corresponding scan result : Malicious/Safe.
        Args:
            scans : Dictionary of the scans.
        Returns:
            technical_detail : markdown table of the scans results.
        """
        technical_detail = utils.table_markdown(scans)
        return technical_detail

    def process(self, message: agent_message.Message) -> None:
        response = self._scan_file(message)

        try:
            scans = self._get_scans(response)
        except VirusTotalApiError:
            logger.error('Virus Total api encountered some problems. Please try again.')

        if scans:
            risk_rating = self._get_risk_rating(scans)
            technical_detail = self._get_technical_details(scans)
            title = 'Some dummmy title to be checked later'
            self.emit(
                'v3.report.event.vulnerability',
                {
                    'title': title,
                    'technical_detail': technical_detail,
                    'risk_rating': risk_rating
                }
            )
