"""Sample agent implementation"""
import ostorlab

class HellWorldAgent(ostorlab.Agent):
    """Hello world agent."""

    def process(self, message: ostorlab.Message) -> None:
        """TODO (author): add your description here.

        Args:
            message:

        Returns:

        """
        # TODO (author): implement agent logic here.
        del message
        self.emit('v3.healthcheck.ping', {'body': 'Hello World!'})
