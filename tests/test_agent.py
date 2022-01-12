"""Unittests for virustotal agent."""
import pytest

from src import virustotal

def testVirusTotalAgent_when_virusTotalApiReturnsValidResponse_noRaiseVirusTotalApiError(
    mocker,
    agent_mock,
    virustotal_agent,
    message):
    """Unittest for the lifecyle of the virustotal agent :
    Sends a dummy malicious file through the virustotal public api,
    receives a valid response, assign a risk rating, creates a technical detail
    and finally emits a message of type v3.report.event.vulnerability with the details above.
    """

    def virustotal_valid_response(message): # pylint: disable=W0613
        """Method for mocking the virustotal public api valid response."""
        response={
            'results':{
                'scans':{
                    'Bkav':{
                        'detected': False, 'version': '1.3.0.9899', 'result': None, 'update': '20220107'
                    },
                    'Elastic': {
                        'detected': True, 'version': '4.0.32', 'result': 'eicar', 'update': '20211223'
                    }
                },
                'scan_id': 'ID42',
                'sha1': 'some_sha1',
                'resource': 'some_ressource_id',
                'response_code': 1,
            },
            'response_code': 200
        }
        return response

    mocker.patch('virus_total_apis.PublicApi.get_file_report', side_effect=virustotal_valid_response)

    try:
        virustotal_agent.process(message)
    except virustotal.VirusTotalApiError:
        pytest.fail('Unexpected VirusTotalApiError because response is returned with status 200.')
    assert len(agent_mock) == 1
    assert agent_mock[0].selector == 'v3.report.event.vulnerability'
    assert agent_mock[0].data['risk_rating'] == 'HIGH'
    assert agent_mock[0].data['title'] == 'VirusTotal report'
    assert isinstance(agent_mock[0].data['technical_detail'], str)
    assert len(agent_mock[0].data['technical_detail']) != 0


def testVirusTotalAgent_when_virusTotalApiReturnsInvalidResponse_raiseVirusTotalApiError(mocker, virustotal_agent, message):
    """Unittest for the lifecyle of the virustotal agent :
    Case where the virustotal pubic api response is invalid.
    """
    def virustotal_invalid_response(message): # pylint: disable=W0613
        """Method for mocking the virustotal public api invalid response."""
        return {
            'response_code': 0,
            'resource': 'some_wrong_ressorce_id',
            'verbose_msg': 'Invalid resource, check what you are submitting'
        }
    mocker.patch('virus_total_apis.PublicApi.get_file_report', side_effect=virustotal_invalid_response)

    with pytest.raises(virustotal.VirusTotalApiError):
        virustotal_agent.process(message)
