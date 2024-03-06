"""Processing scans returned by the Virus Total Public API."""

from typing import Any


from agent import markdown

EXCLUDED_SCANNERS = ["K7GW", "TrendMicro-HouseCall"]


def get_technical_details(scans: dict[str, Any], target: str | None) -> str:
    """Returns a markdown table of the technical report of the scan.
    Each row presents an antivirus with corresponding scan result : Malicious/Safe.

    Args:
        scans : Dictionary of the scans.
        target : target to scan.

    Returns:
        technical_detail : Markdown table of the scans results.
    """
    formatted_scans = markdown.prepare_data_for_markdown_formatting(scans)
    technical_detail = ""
    if target is not None:
        technical_detail = f"Analysis of the target `{target}`:\n"
    technical_detail += markdown.table_markdown(formatted_scans)
    return technical_detail


def is_scan_malicious(scans: dict[str, Any]) -> bool:
    """Checks if any scanner reports the target as malicious.
    Args:
        scans : Dictionary of the scans.

    Returns:
        is_malicious : True if the target is reported as malicious false otherwise.
    """
    for scan_result in scans.values():
        if scan_result["detected"] is True:
            return True

    return False


def exclude_unreliable_scans(scans: dict[str, Any]) -> None:
    """Excludes unreliable reports from the scans.

    Args:
        scans : Dictionary of the scans.
    """
    for scanner in EXCLUDED_SCANNERS:
        try:
            scans.pop(scanner)
        except KeyError:
            continue
