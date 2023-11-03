"""Module responsible for interacting with Virus Total public API."""
import hashlib
from typing import Any
import logging

import virus_total_apis

TIMEOUT_REQUEST = 30

logger = logging.getLogger(__name__)


class Error(Exception):
    """Custom Error."""


class VirusTotalApiError(Error):
    """VirtualTotalApiError."""


def scan_file_from_message(file_content: bytes, api_key: str) -> dict:
    """Method responsible for scanning a file through the Virus Total public API.
    Args:
        file_content: Message containing the file to scan.
        api_key : Key for the virustotal api.
    Returns:
        response: The response of the Virus Total public API.
    """
    file_md5_hash = hashlib.md5(file_content)
    hash_hexa = file_md5_hash.hexdigest()
    virustotal_client = virus_total_apis.PublicApi(api_key)
    response = virustotal_client.get_file_report(hash_hexa)
    return response


def scan_url_from_message(target: str, api_key: str) -> dict:
    """Method responsible for scanning a file through the Virus Total public API.
    Args:
        target: url to scan.
        api_key : Key for the virustotal api.
    Returns:
        response: The response of the Virus Total public API.
    """
    virustotal_client = virus_total_apis.PublicApi(api_key)
    response = virustotal_client.get_url_report(target, timeout=TIMEOUT_REQUEST)
    return response


def get_scans(response: dict[str, Any]) -> dict[str, Any] | None:
    """Method that returns the scans from the Virus Total public API response.

    Args:
        response: Dictionary of the api response.

    Returns:
        scans: Dictionary of the scans.

    Raises:
        VirusTotalApiError: In case the API request encountered problems.
    """
    if response.get("response_code") == 0 or "results" not in response:
        raise VirusTotalApiError()
    elif response["results"]["response_code"] == 1:
        return response["results"]["scans"]
    else:
        return None
