from abc import abstractstaticmethod
import json
import logging

from threading import Timer
from queue import SimpleQueue
from types import FunctionType

import paho.mqtt.client as mqtt

logger = logging.getLogger(__name__)


class MQTTHandler:
    """Simple Handler for MQTT traffic."""

    def __init__(self, client_id: str, host: str):
        self.client = mqtt.Client(
            client_id, userdata=self, protocol=mqtt.MQTTv5
        )
        self.client.connect(host)
        self.client.on_message = self.on_message
        self.client.loop_start()

    def publish(self, topic, msg):
        """Publish Messages via MQTT"""
        self.client.publish(topic, msg)
        logger.debug("Published message on topic %s.", topic)

    @abstractstaticmethod
    def on_message(client, userdata, msg):
        raise NotImplementedError()


class OpenvasMQTTHandler(MQTTHandler):
    """MQTT Handler for Openvas related messages."""

    def __init__(
        self,
        host: str,
        report_result_function: FunctionType,
    ):
        super().__init__(client_id="ospd-openvas", host=host)

        # Set userdata to access handler
        self.client.user_data_set(self)

        # Enable result handling when function is given
        if report_result_function:
            self.res_fun = report_result_function
            self.client.subscribe("scanner/results")
            self.result_dict = {}

    def insert_result(self, result: dict) -> None:
        """Inserts result into a queue. Queue gets emptied after 0.25 seconds
        after first result is inserted"""

        # Get scan ID
        scan_id = result.pop("scan_id")

        # Init result queue
        if not scan_id in self.result_dict:
            self.result_dict[scan_id] = SimpleQueue()

        timer = None
        # Setup Timer when result queue is empty
        if self.result_dict[scan_id].empty():
            timer = Timer(
                0.25,
                self.report_results,
                [self.res_fun, self.result_dict[scan_id], scan_id],
            )

        self.result_dict[scan_id].put(result)

        if timer:
            timer.start()

    @staticmethod
    def report_results(
        res_fun: FunctionType,
        result_queue: SimpleQueue,
        scan_id: str,
    ):
        """Report results with given res_fun."""

        # Create and fill result list
        results_list = []
        while not result_queue.empty():
            results_list.append(result_queue.get())

        # Insert results into scan table
        res_fun(results_list, scan_id)

    @staticmethod
    def on_message(client, userdata, msg):
        """Insert results"""
        try:
            # Load msg as dictionary
            json_data = json.loads(msg.payload)

            # Test for different plugins
            if msg.topic == "scanner/results":
                userdata.insert_result(json_data)
        except json.JSONDecodeError:
            logger.error("Got MQTT message in non-json format.")
            logger.debug("Got: %s", msg.payload)
