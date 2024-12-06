"""Unittests for virustotal agent."""

import pathlib
import re
from typing import Any

import pytest
import requests_mock as rq_mock
from ostorlab.agent.message import message as msg
from pytest_mock import plugin

from agent import virus_total_agent
from agent import virustotal

SECURE_VALID_RESPONSE = {
    "results": {
        "scans": {
            "Bkav": {
                "detected": False,
                "version": "1.3.0.9899",
                "result": None,
                "update": "20220107",
            },
            "Elastic": {
                "detected": False,
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

UNRELIABLE_SCANNERS_RESPONSE = {
    "results": {
        "scans": {
            "TrendMicro-HouseCall": {
                "detected": True,
                "result": None,
                "update": "20240305",
                "version": "2.0.0.8",
            },
            "K7GW": {
                "detected": True,
                "result": None,
                "update": "20240305",
                "version": "23.9.8494.0",
            },
            "Acronis": {
                "detected": False,
                "result": None,
                "update": "20230828",
                "version": "1.2.0.121",
            },
            "AhnLab-V3": {
                "detected": False,
                "result": None,
                "update": "20240305",
                "version": "3.25.1.10473",
            },
            "Alibaba": {
                "detected": False,
                "result": None,
                "update": "20190527",
                "version": "0.3.0.5",
            },
        },
        "scan_id": "ID42",
        "sha1": "some_sha1",
        "resource": "some_ressource_id",
        "response_code": 1,
    },
    "response_code": 200,
}


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
            "permalink": "http://www.virustotal.com/url/1db0ad7dbcec0676710ea0eaacd35d5e471d3e11944d53bcbd31f0cbd11bce31/analysis/1320752364/",
        },
        "response_code": 200,
    }
    return response


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
            "permalink": "https://www.virustotal.com/file/52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c/analysis/1273894724/",
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
    """Unittest for the lifecycle of the virustotal agent :
    Sends a dummy malicious file through the Virus Total public API,
    receives a valid response, assign a risk rating, creates a technical detail
    and finally emits a message of type v3.report.vulnerability with the details above.
    """

    mocker.patch(
        "virus_total_apis.PublicApi.get_file_report",
        side_effect=virustotal_valid_response,
    )
    virustotal_agent.process(message)

    assert len(agent_mock) == 1
    assert all(msg.selector == "v3.report.vulnerability" for msg in agent_mock)
    assert agent_mock[0].data["risk_rating"] == "HIGH"
    assert (
        agent_mock[0].data["title"]
        == "VirusTotal scan flagged malicious asset(s) (MD5 based search)"
    )
    assert isinstance(agent_mock[0].data["technical_detail"], str)
    assert (
        "For more details, visit the [scan report](https://www.virustotal.com/file/52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c/analysis/1273894724/)."
        in agent_mock[0].data["technical_detail"]
    )
    assert all(
        msg.data["short_description"] == "VirusTotal Malware analysis."
        for msg in agent_mock
    )
    assert agent_mock[0].data["references"] == [
        {"title": "Virustotal", "url": "https://www.virustotal.com/"}
    ]


def testVirusTotalAgent_whenVirusTotalApiReturnsInvalidResponse_agentShouldNotCrash(
    mocker: plugin.MockerFixture,
    virustotal_agent: virus_total_agent.VirusTotalAgent,
    message: msg.Message,
) -> None:
    """Unittest for the lifecycle of the virustotal agent :
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
    """Unittest for the lifecycle of the virustotal agent :
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
    assert all(msg.selector == "v3.report.vulnerability" for msg in agent_mock)
    assert agent_mock[0].data["risk_rating"] == "HIGH"
    assert (
        agent_mock[0].data["title"]
        == "VirusTotal scan flagged malicious asset(s) (MD5 based search)"
    )
    assert isinstance(agent_mock[0].data["technical_detail"], str)
    assert (
        "For more details, visit the [scan report]("
        "http://www.virustotal.com/url/1db0ad7dbcec0676710ea0eaacd35d5e471d3e11944d53bcbd31f0cbd11bce31/analysis"
        "/1320752364/)."
    ) in agent_mock[0].data["technical_detail"]
    assert all(
        msg.data["short_description"] == "VirusTotal Malware analysis."
        for msg in agent_mock
    )
    assert agent_mock[0].data["references"] == [
        {"title": "Virustotal", "url": "https://www.virustotal.com/"}
    ]


def testVirusTotalAgent_whenDomainReceived_virusTotalApiReturnsValidResponse(
    mocker: plugin.MockerFixture,
    agent_mock: list[msg.Message],
    virustotal_agent: virus_total_agent.VirusTotalAgent,
    create_domain_message: msg.Message,
) -> None:
    """Unittest for the lifecycle of the virustotal agent :
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
    assert all(msg.selector == "v3.report.vulnerability" for msg in agent_mock)
    assert agent_mock[0].data["risk_rating"] == "HIGH"
    assert (
        agent_mock[0].data["title"]
        == "VirusTotal scan flagged malicious asset(s) (MD5 based search)"
    )
    assert isinstance(agent_mock[0].data["technical_detail"], str)
    assert all(
        msg.data["short_description"] == "VirusTotal Malware analysis."
        for msg in agent_mock
    )
    assert agent_mock[0].data["references"] == [
        {"title": "Virustotal", "url": "https://www.virustotal.com/"}
    ]


def testVirusTotalAgent_whenApisReceived_virusTotalApiReturnsValidResponse(
    mocker: plugin.MockerFixture,
    agent_mock: list[msg.Message],
    virustotal_agent: virus_total_agent.VirusTotalAgent,
    create_network_range_message: msg.Message,
) -> None:
    """Unittest for the lifecycle of the virustotal agent :
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
    assert len([msg for msg in agent_mock if msg.data["risk_rating"] == "HIGH"]) == 14
    assert (
        len(
            [
                msg
                for msg in agent_mock
                if msg.data["title"]
                == "VirusTotal scan flagged malicious asset(s) (MD5 based search)"
            ]
        )
        == 14
    )
    assert isinstance(agent_mock[0].data["technical_detail"], str)
    assert agent_mock[0].data["short_description"] == "VirusTotal Malware analysis."
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
        virustotal_call.last_request.query  # type: ignore
        == "apikey=some_api_key&resource=e29efc13355681a4aa23f0623c2316b9"
    )


def testVirusTotalAgent_whenVirusTotalReachesApiRateLimit_returnNone(
    virustotal_agent: virus_total_agent.VirusTotalAgent,
    message: msg.Message,
) -> None:
    """Unit test for the lifecycle of the virustotal agent :
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
    """Unit test for the lifecycle of the virustotal agent:
    Case when the whitelist_types arg not provided agent shouldn't crash
    """
    mocker.patch("time.sleep")
    get_file_content_mock = mocker.patch(
        "agent.file.get_file_content", return_value=b""
    )

    virustotal_agent.process(message)

    assert get_file_content_mock.call_count == 1


def testVirusTotalAgent_whenFileHasNoPath_shouldReportWithHash(
    mocker: plugin.MockerFixture,
    virustotal_agent: virus_total_agent.VirusTotalAgent,
    message_without_path: msg.Message,
    agent_mock: list[msg.Message],
) -> None:
    """Test that the target value defaults back to the file hash."""
    mocker.patch(
        "virus_total_apis.PublicApi.get_file_report",
        side_effect=virustotal_valid_response,
    )

    virustotal_agent.process(message_without_path)

    assert len(agent_mock) == 1
    assert (
        agent_mock[0].data["technical_detail"]
        == """Analysis of the target `44d88612fea8a8f36de82e1278abb02f`:
|Package|  Result  |  
|-------|----------|  
|Bkav   |_Safe_    |  
|Elastic|_Malicous_|  

For more details, visit the [scan report](https://www.virustotal.com/file/52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c/analysis/1273894724/)."""
    )


def testVirusTotalAgent_whenIPv4AssetReachCIDRLimit_raiseValueError(
    scan_message_ipv4_with_mask8: msg.Message,
    virustotal_agent: virus_total_agent.VirusTotalAgent,
) -> None:
    """Test the CIDR Limit in case IPV4 and the Limit is reached."""
    with pytest.raises(ValueError, match="Subnet mask below 16 is not supported."):
        virustotal_agent.process(scan_message_ipv4_with_mask8)


def testVirusTotalAgent_whenIPv4AssetDoesNotReachCIDRLimit_doesNotRaiseValueError(
    mocker: plugin.MockerFixture,
    scan_message_ipv4_with_mask16: msg.Message,
    virustotal_agent: virus_total_agent.VirusTotalAgent,
) -> None:
    """Test the CIDR Limit in case IPV4 and the Limit is not reached."""
    mocker.patch(
        "agent.virustotal.scan_url_from_message",
        return_value={},
    )

    virustotal_agent.process(scan_message_ipv4_with_mask16)


def testVirusTotalAgent_whenIPv6AssetReachCIDRLimit_raiseValueError(
    scan_message_ipv6_with_mask64: msg.Message,
    virustotal_agent: virus_total_agent.VirusTotalAgent,
) -> None:
    """Test the CIDR Limit in case IPV6 and the Limit is reached."""
    with pytest.raises(ValueError, match="Subnet mask below 112 is not supported."):
        virustotal_agent.process(scan_message_ipv6_with_mask64)


def testVirusTotalAgent_whenIPv6AssetDoesNotReachCIDRLimit_doesNotRaiseValueError(
    mocker: plugin.MockerFixture,
    scan_message_ipv6_with_mask112: msg.Message,
    virustotal_agent: virus_total_agent.VirusTotalAgent,
) -> None:
    """Test the CIDR Limit in case IPV6 and the Limit is not reached."""
    mocker.patch(
        "agent.virustotal.scan_url_from_message",
        return_value={},
    )

    virustotal_agent.process(scan_message_ipv6_with_mask112)


def testVirusTotalAgent_whenIPAssetHasIncorrectVersion_raiseValueError(
    scan_message_ipv_with_incorrect_version: msg.Message,
    virustotal_agent: virus_total_agent.VirusTotalAgent,
) -> None:
    """Test the CIDR Limit in case IP has incorrect version."""
    with pytest.raises(ValueError, match="Incorrect ip version 5."):
        virustotal_agent.process(scan_message_ipv_with_incorrect_version)


def testVirusTotalAgent_whenReportIsSecure_shouldReportAsSecure(
    mocker: plugin.MockerFixture,
    virustotal_agent: virus_total_agent.VirusTotalAgent,
    message_without_path: msg.Message,
    agent_mock: list[msg.Message],
) -> None:
    """Test that the agent report secure reports with correct kb entry."""

    def virustotal_secure_valid_response(message: msg.Message) -> dict[str, Any]:
        """Method for mocking the Virus Total public API valid response."""
        del message
        return SECURE_VALID_RESPONSE

    mocker.patch(
        "virus_total_apis.PublicApi.get_file_report",
        side_effect=virustotal_secure_valid_response,
    )

    virustotal_agent.process(message_without_path)

    assert len(agent_mock) == 1
    assert agent_mock[0].data["risk_rating"] == "SECURE"
    assert agent_mock[0].selector == "v3.report.vulnerability"
    assert agent_mock[0].data["technical_detail"] == (
        "Analysis of the target `44d88612fea8a8f36de82e1278abb02f`:\n|Package|Result|"
        "  \n|-------|------|  \n|Bkav   |_Safe_|  \n|Elastic|_Safe_|  \n"
    )
    assert (
        agent_mock[0].data["title"]
        == "Secure Virustotal malware analysis (MD5 based search)"
    )
    assert agent_mock[0].data["short_description"] == "VirusTotal Malware analysis."
    assert agent_mock[0].data["references"] == [
        {"title": "Virustotal", "url": "https://www.virustotal.com/"}
    ]


def testVirusTotalAgent_whenScannerIsExcluded_shouldNotBeConsidered(
    mocker: plugin.MockerFixture,
    virustotal_agent: virus_total_agent.VirusTotalAgent,
    message_without_path: msg.Message,
    agent_mock: list[msg.Message],
) -> None:
    """Test that the agent exclude the unreliable scanners specified."""

    def virustotal_unreliable_scanner_response(message: None) -> dict[str, Any]:
        """Method for mocking the Virus Total public API unreliable scanner response."""
        del message
        return UNRELIABLE_SCANNERS_RESPONSE

    mocker.patch(
        "virus_total_apis.PublicApi.get_file_report",
        side_effect=virustotal_unreliable_scanner_response,
    )

    virustotal_agent.process(message_without_path)

    assert len(agent_mock) == 1
    assert agent_mock[0].data["risk_rating"] == "SECURE"
    assert agent_mock[0].selector == "v3.report.vulnerability"
    assert "K7GW" not in agent_mock[0].data["technical_detail"]
    assert "TrendMicro-HouseCall" not in agent_mock[0].data["technical_detail"]
    assert agent_mock[0].data["technical_detail"] == (
        "Analysis of the target `44d88612fea8a8f36de82e1278abb02f`:\n| Package |Result|"
        "  \n|---------|------|  \n|Acronis  |_Safe_|  \n|AhnLab-V3|_Safe_|  \n|Alibaba  |_Safe_|  \n"
    )
    assert (
        agent_mock[0].data["title"]
        == "Secure Virustotal malware analysis (MD5 based search)"
    )
    assert agent_mock[0].data["short_description"] == "VirusTotal Malware analysis."
    assert agent_mock[0].data["references"] == [
        {"title": "Virustotal", "url": "https://www.virustotal.com/"}
    ]
