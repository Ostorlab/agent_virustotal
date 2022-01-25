"""Module responsible for interacting with Virus Total public API."""
from typing import Dict
import hashlib

import virus_total_apis
from ostorlab.agent import message as agent_message

class Error(Exception):
    """Custom Error."""


class VirusTotalApiError(Error):
    """VirtualTotalApiError."""

def scan_file_from_message(message: agent_message.Message, api_key: str) -> Dict:
    """Method responsible for scanning a file through the Virus Total public API.
    Args:
        message: Message containing the file to scan.
        api_key : Key for the virustotal api.
    Returns:
        response: The response of the Virus Total public API.
    """
    file = message.data['content'].encode('utf-8')
    file_md5_hash = hashlib.md5(file)
    hash_hexa = file_md5_hash.hexdigest()
    virustotal_client = virus_total_apis.PublicApi(api_key)
    response = virustotal_client.get_file_report(hash_hexa)
    return response


def get_scans(response: Dict) -> Dict:
    """Method that returns the scans from the Virus Total public API response.
    Args:
        response: Dictionary of the api response.
    Returns:
        scans: Dictionary of the scans.
    Raises:
        VirusTotalApiError: In case the API request encountered problems.
    """
    if response['response_code'] == 0 or 'results' not in response:
        raise VirusTotalApiError
    elif response['results']['response_code'] == 1:
        return response['results']['scans']
    else:
        return None
