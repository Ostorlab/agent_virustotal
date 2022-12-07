"""Module responsible for markdown formatting."""
from typing import Dict, List
import io

from pytablewriter import MarkdownTableWriter


def prepare_data_for_markdown_formatting(scans: Dict) -> List[List[str]]:
    """Method responsible for formatting the data into the correct form for the MarkdownTableWriter.

    Args:
        scans: Dictionary containing the scans, from the virustotal api response.

    Returns:
        data: List of lists, each containing the name of the antivirus, and the result of its scan.
    """
    data = []
    for antivirus, result in scans.items():
        status = "_Malicous_" if result["detected"] is True else "_Safe_"
        row = [antivirus, status]
        data.append(row)
    return data


def table_markdown(data: List[List[str]]) -> str:
    """Method responsible for generating a markdown table from a dictionary.

    Args:
        data: List of the data to be transformed into markdown table.

    Returns:
        table: Complete markdown table
    """
    headers = ["Package", "Result"]
    markdown_writer = MarkdownTableWriter(headers=headers, value_matrix=data)
    markdown_writer.stream = io.StringIO()
    markdown_writer.write_table()
    table = markdown_writer.stream.getvalue()
    table = table.replace("\n", "  \n")  # Two spaces \n for a new line  in markdown.

    return table
