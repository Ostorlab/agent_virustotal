"""Pytest fixtures for the virustotal agent."""
import pathlib

import pytest
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message as msg
from ostorlab.runtimes import definitions as runtime_definitions

from agent import virus_total_agent


@pytest.fixture(name="message")
def create_scan_message() -> msg.Message:
    """Creates a dummy message of type v3.asset.file to be used by the agent for testing purposes.
    The files used is the EICAR Anti-Virus Test File.
    """
    file_content = (
        pathlib.Path(__file__).parents[0] / "files/malicious_dummy.com"
    ).read_bytes()
    selector = "v3.asset.file"
    msg_data = {"content": file_content, "path": "some/dummy/path"}
    return msg.Message.from_data(selector, data=msg_data)


@pytest.fixture(name="url_message")
def create_url_scan_message() -> msg.Message:
    """Creates a dummy message of type v3.asset.link to be used by the agent for testing purposes.
    The files used is the EICAR Anti-Virus Test File.
    """
    selector = "v3.asset.link"
    msg_data = {"url": "https://virus.com", "method": "GET"}
    return msg.Message.from_data(selector, data=msg_data)


@pytest.fixture
def create_network_range_message() -> msg.Message:
    """Creates a dummy message of type v3.asset.ip.v4 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v4"
    msg_data = {"host": "209.235.136.112", "mask": "28", "version": 4}
    return msg.Message.from_data(selector, data=msg_data)


@pytest.fixture
def create_domain_message() -> msg.Message:
    """Creates a dummy message of type v3.asset.domain_name to be used by the agent for testing purposes."""
    selector = "v3.asset.domain_name"
    msg_data = {"name": "apple.com"}
    return msg.Message.from_data(selector, data=msg_data)


@pytest.fixture(name="virustotal_agent")
def create_virustotal_agent(
    agent_mock: list[msg.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> virus_total_agent.VirusTotalAgent:
    """Instantiate a virustotal agent."""

    del agent_mock, agent_persist_mock
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        definition.args = [
            {
                "name": "api_key",
                "type": "string",
                "value": "some_api_key",
                "description": "Api key for the virus total API.",
            },
            {
                "name": "whitelist_types",
                "type": "array",
                "description": "List of mimetypes types to whitelist for scanning.",
            },
        ]
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/agent_virustotal_key",
            redis_url="redis://guest:guest@localhost:6379",
        )

        agent = virus_total_agent.VirusTotalAgent(
            definition,
            settings,
        )
        return agent


@pytest.fixture
def virustotal_agent_with_whitelist() -> virus_total_agent.VirusTotalAgent:
    """Instantiate a virustotal agent."""
    definition = agent_definitions.AgentDefinition(
        name="agent_virustotal",
        in_selectors=["v3.asset.file"],
        out_selectors=["v3.report.vulnerability"],
        args=[
            {
                "name": "api_key",
                "type": "string",
                "value": "some_api_key",
                "description": "Api key for the virus total API.",
            },
            {
                "name": "whitelist_types",
                "type": "list",
                "value": ["application/zip"],
                "description": "List of mime types to whitelist.",
            },
        ],
    )

    settings = runtime_definitions.AgentSettings(
        key="agent_virustotal_key",
        bus_url="NA",
        bus_exchange_topic="NA",
    )

    agent = virus_total_agent.VirusTotalAgent(
        definition,
        settings,
    )

    return agent


@pytest.fixture()
def message_without_path() -> msg.Message:
    """Creates a dummy message of type v3.asset.file without a path attribute."""
    file_content = (
        pathlib.Path(__file__).parents[0] / "files/malicious_dummy.com"
    ).read_bytes()
    selector = "v3.asset.file"
    msg_data = {"content": file_content}
    return msg.Message.from_data(selector, data=msg_data)
