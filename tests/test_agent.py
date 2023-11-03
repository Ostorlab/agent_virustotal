"""Unittests for virustotal agent."""
import pathlib
import re
from typing import Any
import requests_mock as rq_mock

import pytest
from ostorlab.agent.message import message as msg
from pytest_mock import plugin

from agent import virus_total_agent
from agent import virustotal


def virustotal_url_valid_response(url: str, timeout: int) -> dict[str, Any]:
    """Method for mocking the Virus Total public API valid response."""
    del url, timeout
    response = {
        "results": {
            "scans": {
                "Bkav": {
                    "detected": False,
                    "version": "1.3.0.9899",
                    "result": None,
                    "update": "20220107",
                },
                "Elastic": {
                    "detected": True,
                    "version": "4.0.32",
                    "result": "eicar",
                    "update": "20211223",
                },
            },
            "scan_id": "ID42",
            "sha1": "some_sha1",
            "resource": "some_ressource_id",
            "response_code": 1,
        },
        "response_code": 200,
    }
    return response


def testVirusTotalAgent_whenVirusTotalApiReturnsValidResponse_noExceptionRaised(
    mocker: plugin.MockerFixture,
    agent_mock: list[msg.Message],
    virustotal_agent: virus_total_agent.VirusTotalAgent,
    message: msg.Message,
) -> None:
    """Unittest for the lifecyle of the virustotal agent :
    Sends a dummy malicious file through the Virus Total public API,
    receives a valid response, assign a risk rating, creates a technical detail
    and finally emits a message of type v3.report.vulnerability with the details above.
    """

    def virustotal_valid_response(message: msg.Message) -> dict[str, Any]:
        """Method for mocking the Virus Total public API valid response."""
        del message
        response = {
            "results": {
                "scans": {
                    "Bkav": {
                        "detected": False,
                        "version": "1.3.0.9899",
                        "result": None,
                        "update": "20220107",
                    },
                    "Elastic": {
                        "detected": True,
                        "version": "4.0.32",
                        "result": "eicar",
                        "update": "20211223",
                    },
                },
                "scan_id": "ID42",
                "sha1": "some_sha1",
                "resource": "some_ressource_id",
                "response_code": 1,
            },
            "response_code": 200,
        }
        return response

    mocker.patch(
        "virus_total_apis.PublicApi.get_file_report",
        side_effect=virustotal_valid_response,
    )
    virustotal_agent.process(message)

    assert len(agent_mock) == 1
    assert agent_mock[0].selector == "v3.report.vulnerability"
    assert agent_mock[0].data["risk_rating"] == "HIGH"
    assert (
        agent_mock[0].data["title"] == "Virustotal malware analysis (MD5 based search)"
    )
    assert isinstance(agent_mock[0].data["technical_detail"], str)
    assert agent_mock[0].data["short_description"] == "VirusTotal Malware analysis."
    assert agent_mock[0].data["privacy_issue"]
    assert agent_mock[0].data["security_issue"]
    assert agent_mock[0].data["references"] == [
        {"title": "Virustotal", "url": "https://www.virustotal.com/"}
    ]


def testVirusTotalAgent_whenVirusTotalApiReturnsInvalidResponse_agentShouldNotCrash(
    mocker: plugin.MockerFixture,
    virustotal_agent: virus_total_agent.VirusTotalAgent,
    message: msg.Message,
) -> None:
    """Unittest for the lifecyle of the virustotal agent :
    Case where the Virus Total public API response is invalid.
    """
    mocker.patch("time.sleep")

    def virustotal_invalid_response(message: msg.Message) -> dict[str, Any]:
        """Method for mocking the virustotal public api invalid response."""
        del message
        return {
            "response_code": 0,
            "resource": "some_wrong_resource_id",
            "verbose_msg": "Invalid resource, check what you are submitting",
        }

    mocker.patch(
        "virus_total_apis.PublicApi.get_file_report",
        side_effect=virustotal_invalid_response,
    )
    get_scans_mocker = mocker.patch("agent.virustotal.get_scans")

    virustotal_agent.process(message)

    assert get_scans_mocker.call_count == 1


def testVirusTotalAgent_whenLinkReceived_virusTotalApiReturnsValidResponse(
    mocker: plugin.MockerFixture,
    agent_mock: list[msg.Message],
    virustotal_agent: virus_total_agent.VirusTotalAgent,
    url_message: msg.Message,
) -> None:
    """Unittest for the lifecyle of the virustotal agent :
    Sends a dummy malicious url through the Virus Total public API,
    receives a valid response, assign a risk rating, creates a technical detail
    and finally emits a message of type v3.report.vulnerability with the details above.
    """
    mocker.patch(
        "virus_total_apis.PublicApi.get_url_report",
        side_effect=virustotal_url_valid_response,
    )

    virustotal_agent.process(url_message)

    assert len(agent_mock) == 1
    assert agent_mock[0].selector == "v3.report.vulnerability"
    assert agent_mock[0].data["risk_rating"] == "HIGH"
    assert (
        agent_mock[0].data["title"] == "Virustotal malware analysis (MD5 based search)"
    )
    assert isinstance(agent_mock[0].data["technical_detail"], str)
    assert agent_mock[0].data["short_description"] == "VirusTotal Malware analysis."
    assert agent_mock[0].data["privacy_issue"]
    assert agent_mock[0].data["security_issue"]
    assert agent_mock[0].data["references"] == [
        {"title": "Virustotal", "url": "https://www.virustotal.com/"}
    ]


def testVirusTotalAgent_whenDomainReceived_virusTotalApiReturnsValidResponse(
    mocker: plugin.MockerFixture,
    agent_mock: list[msg.Message],
    virustotal_agent: virus_total_agent.VirusTotalAgent,
    create_domain_message: msg.Message,
) -> None:
    """Unittest for the lifecyle of the virustotal agent :
    Sends a dummy malicious domain through the Virus Total public API,
    receives a valid response, assign a risk rating, creates a technical detail
    and finally emits a message of type v3.report.vulnerability with the details above.
    """
    mocker.patch(
        "virus_total_apis.PublicApi.get_url_report",
        side_effect=virustotal_url_valid_response,
    )

    virustotal_agent.process(create_domain_message)

    assert len(agent_mock) == 1
    assert agent_mock[0].selector == "v3.report.vulnerability"
    assert agent_mock[0].data["risk_rating"] == "HIGH"
    assert (
        agent_mock[0].data["title"] == "Virustotal malware analysis (MD5 based search)"
    )
    assert isinstance(agent_mock[0].data["technical_detail"], str)
    assert agent_mock[0].data["short_description"] == "VirusTotal Malware analysis."
    assert agent_mock[0].data["privacy_issue"]
    assert agent_mock[0].data["security_issue"]
    assert agent_mock[0].data["references"] == [
        {"title": "Virustotal", "url": "https://www.virustotal.com/"}
    ]


def testVirusTotalAgent_whenApisReceived_virusTotalApiReturnsValidResponse(
    mocker: plugin.MockerFixture,
    agent_mock: list[msg.Message],
    virustotal_agent: virus_total_agent.VirusTotalAgent,
    create_network_range_message: msg.Message,
) -> None:
    """Unittest for the lifecyle of the virustotal agent :
    Sends a dummy malicious IP range through the Virus Total public API,
    receives a valid response, assign a risk rating, creates a technical detail
    and finally emits a message of type v3.report.vulnerability with the details above.
    """
    mocker.patch(
        "virus_total_apis.PublicApi.get_url_report",
        side_effect=virustotal_url_valid_response,
    )

    virustotal_agent.process(create_network_range_message)

    assert len(agent_mock) == 14
    assert agent_mock[0].selector == "v3.report.vulnerability"
    assert agent_mock[0].data["risk_rating"] == "HIGH"
    assert (
        agent_mock[0].data["title"] == "Virustotal malware analysis (MD5 based search)"
    )
    assert isinstance(agent_mock[0].data["technical_detail"], str)
    assert agent_mock[0].data["short_description"] == "VirusTotal Malware analysis."
    assert agent_mock[0].data["privacy_issue"]
    assert agent_mock[0].data["security_issue"]
    assert agent_mock[0].data["references"] == [
        {"title": "Virustotal", "url": "https://www.virustotal.com/"}
    ]


def testVirusTotalAgent_whenWhitelistTypesIsSet_agentShouldIgnoreNonWhitelisted(
    mocker: plugin.MockerFixture,
    agent_mock: list[msg.Message],
    virustotal_agent_with_whitelist: virus_total_agent.VirusTotalAgent,
    message: msg.Message,
    requests_mock: rq_mock.mocker.Mocker,
) -> None:
    """Test when file is not whitelisted, agent should not call the Virus Total public API."""
    dummy_zip = pathlib.Path(__file__).parent / "files/dummy1.txt"
    zip_message = msg.Message.from_data(
        "v3.asset.file", data={"content": dummy_zip.read_bytes()}
    )
    virustotal_call = requests_mock.get(
        re.compile("https://www.virustotal.com/vtapi/v2/file/*"),
        json=virustotal_url_valid_response,
    )

    virustotal_agent_with_whitelist.process(zip_message)

    assert virustotal_call.called is False


def testVirusTotalAgent_whenFileIsWhitelisted_agentShouldScanFile(
    mocker: plugin.MockerFixture,
    agent_mock: list[msg.Message],
    virustotal_agent_with_whitelist: virus_total_agent.VirusTotalAgent,
    message: msg.Message,
    requests_mock: rq_mock.mocker.Mocker,
) -> None:
    """Test when file whitelisted, agent should call the Virus Total public API."""
    dummy_zip = pathlib.Path(__file__).parent / "files/dummy.zip"
    zip_message = msg.Message.from_data(
        "v3.asset.file", data={"content": dummy_zip.read_bytes()}
    )
    virustotal_call = requests_mock.get(
        re.compile("https://www.virustotal.com/vtapi/v2/file/*"),
        json=virustotal_url_valid_response,
    )

    virustotal_agent_with_whitelist.process(zip_message)

    assert virustotal_call.called is True
    assert (
        virustotal_call.last_request.query
        == "apikey=some_api_key&resource=e29efc13355681a4aa23f0623c2316b9"
    )


def testVirusTotalAgent_whenVirusTotalReachesApiRateLimit_returnNone(
    virustotal_agent: virus_total_agent.VirusTotalAgent,
    message: msg.Message,
) -> None:
    """Unit test for the lifecyle of the virustotal agent :
    Case where the Virus Total public API reached the rate limit.
    """

    response = {
        "error": "You exceeded the public API request rate limit (4 requests of any nature per minute)",
        "response_code": 204,
    }

    scans = virustotal.get_scans(response)

    assert scans is None


def testVirusTotalAgent_whenWhiteListTypesAreNotProvided_shouldNotCrash(
    mocker: plugin.MockerFixture,
    virustotal_agent: virus_total_agent.VirusTotalAgent,
    message: msg.Message,
) -> None:
    """Unit test for the lifecyle of the virustotal agent:
    Case when the whitelist_types arg not provided agent shouldn't crash
    """
    mocker.patch("time.sleep")
    get_file_content_mock = mocker.patch(
        "agent.file.get_file_content", return_value=b""
    )

    virustotal_agent.process(message)

    assert get_file_content_mock.call_count == 1
