import json
import logging

from threading import Timer
from queue import SimpleQueue

import paho.mqtt.client as mqtt

logger = logging.getLogger(__name__)


class MQTTHandler:
    """Simple Handler for MQTT traffic."""

    def __init__(self, client_id: str, host: str):
        self.client = mqtt.Client(client_id, userdata=self)
        self.client.connect(host)
        self.client.on_message = self.on_message
        self.client.loop_start()

    @staticmethod
    def on_message(client, userdata, msg):
        return


class OpenvasMQTTHandler(MQTTHandler):
    """MQTT Handler for Openvas related messages."""

    def __init__(
        self,
        host: str,
        publish_result_function=None,
        publish_stat_function=None,
    ):
        super().__init__(client_id="ospd-openvas", host=host)

        # Set userdata to access handler
        self.client.user_data_set(self)

        # Enable result handling when function is given
        if publish_result_function:
            self.res_fun = publish_result_function
            self.result_timer = {}
            self.client.subscribe("scanner/results")
            self.result_dict = {}

        # Enable status handling when function is given
        if publish_stat_function:
            self.stat_fun = publish_stat_function
            self.client.subscribe("scanner/status")

    def insert_result(self, result: dict) -> None:
        """Insert given results into a list corresponding to the scan_id"""
        # Get Scan ID
        scan_id = result.pop("scan_id")

        # Reset Pub Timer for Scan ID
        if scan_id in self.result_timer:
            self.result_timer[scan_id].cancel()

        # Create List for new Scan ID
        if not scan_id in self.result_dict:
            self.result_dict[scan_id] = SimpleQueue()

        # Append Result for ID
        self.result_dict[scan_id].put(result)

        # Set Timer for publishing results
        self.result_timer[scan_id] = Timer(
            1,
            self.publish_results,
            [self.res_fun, self.result_dict[scan_id], scan_id],
        )
        self.result_timer[scan_id].start()

    @staticmethod
    def publish_results(res_fun, result_queue: SimpleQueue, scan_id: str):
        results_list = []
        while not result_queue.empty():
            results_list.append(result_queue.get())
        res_fun(results_list, scan_id)

    def set_status(self, status: dict) -> None:
        # Get Scan ID
        scan_id = status.pop("scan_id")
        logger.debug("Got status update from: %s", scan_id)

    @staticmethod
    def on_message(client, userdata, msg):
        logger.debug("Got MQTT message in topic %s", msg.topic)
        try:
            # Load msg as dictionary
            json_data = json.loads(msg.payload)
            print(msg.topic)

            # Test for different plugins
            if msg.topic == "scanner/results":
                userdata.insert_result(json_data)
        except json.JSONDecodeError:
            logger.error("Got MQTT message in non-json format.")
