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
        self.client = mqtt.Client(client_id, userdata=self)
        self.client.connect(host)
        self.client.on_message = self.on_message
        self.client.loop_start()

    def publish(self, topic, msg):
        """Publish Messages via MQTT"""

        self.client.publish(topic, msg)

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
            self.result_timer_min = {}
            self.result_timer_max = {}
            self.client.subscribe("scanner/results")
            self.result_dict = {}

    def insert_result(self, result: dict) -> None:
        """Insert given results into a list corresponding to the scan_id and
        reports them after 0.5 seconds without new incoming results or after
        a maximum of 10 seconds."""

        # Get scan ID
        scan_id = result.pop("scan_id")

        # Reset min timer
        if scan_id in self.result_timer_min:
            self.result_timer_min[scan_id].cancel()
        else:
            self.result_timer_min[scan_id] = None

        # Init result queue
        if not scan_id in self.result_dict:
            self.result_dict[scan_id] = SimpleQueue()

        self.result_dict[scan_id].put(result)

        # Start max timer if it is not running
        if (
            not scan_id in self.result_timer_max
            or scan_id in self.result_timer_max
            and not self.result_timer_max[scan_id].is_alive()
        ):
            self.result_timer_max[scan_id] = Timer(
                10,
                self.report_results,
                [
                    self.res_fun,
                    self.result_dict[scan_id],
                    scan_id,
                    self.result_timer_min[scan_id],
                ],
            )
            self.result_timer_max[scan_id].start()

        # Start min timer
        self.result_timer_min[scan_id] = Timer(
            0.5,
            self.report_results,
            [
                self.res_fun,
                self.result_dict[scan_id],
                scan_id,
                self.result_timer_max[scan_id],
            ],
        )
        self.result_timer_min[scan_id].start()

    def report_results(
        self,
        res_fun,
        result_queue: SimpleQueue,
        scan_id: str,
        timer_to_reset: Timer = None,
    ):
        """Report results with given res_fun."""
        if timer_to_reset:
            timer_to_reset.cancel()
        results_list = []
        while not result_queue.empty():
            results_list.append(result_queue.get())
        res_fun(results_list, scan_id)
        if timer_to_reset:
            timer_to_reset.join()

    @staticmethod
    def on_message(client, userdata, msg):
        """Insert results"""
        logger.debug("Got MQTT message in topic %s", msg.topic)
        try:
            # Load msg as dictionary
            json_data = json.loads(msg.payload)

            # Test for different plugins
            if msg.topic == "scanner/results":
                userdata.insert_result(json_data)
        except json.JSONDecodeError:
            logger.error("Got MQTT message in non-json format.")
            logger.debug("Got: %s", msg.payload)
