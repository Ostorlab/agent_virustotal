"""Tests for file"""

import requests_mock as rq_mock
from ostorlab.agent.message import message as m

from agent import file


def testGetFileContent_whenContentIsNotNone_returnTheContent() -> None:
    """Test that the content is returned when it is not empty."""
    message = m.Message.from_data(
        selector="v3.asset.file.android.apk", data={"content": b"content"}
    )

    content = file.get_file_content(message)

    assert content == b"content"


def testGetFileContent_whenContentIsEmpty_shouldTryToDownloadTheFile(
    requests_mock: rq_mock.mocker.Mocker,
) -> None:
    """Test that the file is downloaded when the content is empty."""
    message = m.Message.from_data(
        selector="v3.asset.file.android.apk",
        data={"content_url": "https://example.com/legendary.apk"},
    )
    requests_mock.get(
        "https://example.com/legendary.apk", content=b"downloaded_content"
    )

    content = file.get_file_content(message)

    assert content == b"downloaded_content"


def testGetFileContent_whenNoContentIsAvailable_shouldReturnNone() -> None:
    """Test that None is returned when no content is available."""
    message = m.Message.from_data(selector="v3.asset.file.android.apk", data={})

    content = file.get_file_content(message)

    assert content is None
