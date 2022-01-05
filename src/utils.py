"""Utils for the virustotal agent.
Provides helping methods for preparing the scans & creating the markdown table.
Data should be made into  the following form :
data = [
    {'header1': 'row1col1', 'header2': 'row1col2'},
    {'header1': 'row2col1', 'header2': 'row2col2'}
]
"""
from typing import Dict, List
import markdownTable

def prepare_data_for_markdown_formatting(scans:Dict) -> List[Dict]:
    """Method responsible for formatting the data into the correct form for the table_markdown method.
    Args:
        scans: Dictionary containing the scans, from the virustotal response.
    Returns:
        data: List of dictionaries each dictionary with header names as keys, and rows as values.
    """
    header = ['Package', 'Result']
    data = []
    for antivirus, result in scans.items():
        status = '_Malicous_' if result['detected'] is True else '_Safe_'
        row = {header[0]:antivirus, header[1]:status}
        data.append(row)
    return data

def table_markdown(data: Dict, padding_width: int =2) -> str:
    """Method responsible for generating a markdown table from a dictionary.
    Args:
        data: Dictionary of the data to be transformed into markdown table.
        padding_width: Extra padding to all table cells
    Returns:
        table: Complete escaped markdown table
    """
    table = markdownTable.markdownTable(data).setParams(row_sep = 'always', padding_width=padding_width).getMarkdown()
    return table
