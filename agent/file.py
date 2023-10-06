"""Collection of functions to handle files."""
import requests
import tenacity
from ostorlab.agent.message import message as m

DOWNLOAD_REQUEST_TIMEOUT = 60
NUMBER_RETRIES = 3


@tenacity.retry(
    stop=tenacity.stop_after_attempt(NUMBER_RETRIES),
    retry=tenacity.retry_if_exception_type(),
    retry_error_callback=lambda retry_state: retry_state.outcome.result()
    if retry_state.outcome is not None
    else None,
)
def _download_file(file_url: str) -> bytes | None:
    """Download a file.

    Args:
        file_url : The URL of the file to download.

    Returns:
        bytes: The content of the file.
    """
    response = requests.get(file_url, timeout=DOWNLOAD_REQUEST_TIMEOUT)
    if response.status_code == 200:
        return response.content

    return None


def get_file_content(message: m.Message) -> bytes | None:
    """Get the file content from a message.

    Args:
        message : The message containing the file info.

    Returns:
        bytes: The content of the file.
    """
    content = message.data.get("content")
    if content is not None and isinstance(content, bytes):
        return content
    content_url: str | None = message.data.get("content_url")
    if content_url is not None:
        file_content: bytes | None = _download_file(content_url)
        return file_content
