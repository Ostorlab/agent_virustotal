"""Pytest fixtures for the virustotal agent."""
import pytest

from ostorlab.agent import message
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions

from src import agent as virustotal_agent


@pytest.fixture(name='message')
def create_scan_message():
    """Creates a dummy message of type v3.asset.file to be used by the agent for testing purposes.
    The files used is the EICAR Anti-Virus Test File.
    """
    with open('./files/malicious_dummy.com', 'rb') as f:
        file_content = f.read()
        selector = 'v3.asset.file'
        msg_data = {'content': file_content, 'path': 'some/dummy/path'}
        return message.Message.from_data(selector, data=msg_data)

@pytest.fixture(name='virustotal_agent')
def create_virustotal_agent():
    """Instantiate a virustotal agent."""
    definition = agent_definitions.AgentDefinition(
        name='agent_virustotal',
        in_selectors = ['v3.healthcheck.ping', 'v3.asset.file'],
        out_selectors=['v3.report.event.vulnerability']
    )

    settings = runtime_definitions.AgentSettings(
        key='agent_virustotal_key',
        bus_url='NA',
        bus_exchange_topic='NA',
    )

    agent = virustotal_agent.VirusTotalAgent(
        definition,
        settings,
        api_key='some_dumy_api_key'
    )

    return agent
