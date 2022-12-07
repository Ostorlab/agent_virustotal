"""Module responsible for interacting with Virus Total public API."""
import hashlib
from typing import Optional, Dict

import virus_total_apis
from ostorlab.agent.message import message as msg


class Error(Exception):
    """Custom Error."""


class VirusTotalApiError(Error):
    """VirtualTotalApiError."""


def scan_file_from_message(message: msg.Message, api_key: str) -> Dict:
    """Method responsible for scanning a file through the Virus Total public API.
    Args:
        message: Message containing the file to scan.
        api_key : Key for the virustotal api.
    Returns:
        response: The response of the Virus Total public API.
    """
    file = message.data["content"]
    file_md5_hash = hashlib.md5(file)
    hash_hexa = file_md5_hash.hexdigest()
    virustotal_client = virus_total_apis.PublicApi(api_key)
    response = virustotal_client.get_file_report(hash_hexa)
    return response


def get_scans(response: Dict) -> Optional[Dict]:
    """Method that returns the scans from the Virus Total public API response.

    Args:
        response: Dictionary of the api response.

    Returns:
        scans: Dictionary of the scans.

    Raises:
        VirusTotalApiError: In case the API request encountered problems.
    """
    if response["response_code"] == 0 or "results" not in response:
        raise VirusTotalApiError()
    elif response["results"]["response_code"] == 1:
        return response["results"]["scans"]
    else:
        return None
