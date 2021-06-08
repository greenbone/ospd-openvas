import logging
import time

from unittest.case import TestCase
from unittest.mock import MagicMock, patch

from paho.mqtt.client import MQTTMessage

from ospd_openvas.mqtt import MQTTHandler, OpenvasMQTTHandler


@patch('paho.mqtt.client.Client', autospec=True)
class TestMQTT(TestCase):
    def test_on_message_not_implemented(self, mock_client: MagicMock):
        mqtt = MQTTHandler("foo", "bar")

        with self.assertRaises(NotImplementedError):
            mqtt.on_message(None, None, None)

    def test_publish_message(self, mock_client: MagicMock):
        mqtt = MQTTHandler("foo", "bar")

        logging.Logger.debug = MagicMock()

        mqtt.publish("foo/bar", "test123")

        logging.Logger.debug.assert_called_with(  # pylint: disable=no-member
            'Published message on topic %s.', "foo/bar"
        )

    def test_insert_results(self, mock_client: MagicMock):

        results_dict = {}
        expct_dict = {
            "1": [
                {
                    "type": "foo",
                    "host_ip": "127.0.0.1",
                    "hostname": "",
                    "port": "80",
                    "OID": "",
                    "value": "bar",
                }
            ]
        }

        msg = MQTTMessage()
        msg.topic = b"scanner/results"
        msg.payload = b'{"scan_id":"1","type":"foo","host_ip":"127.0.0.1","hostname":"","port":"80","OID":"","value":"bar"}'

        def add_results(results, scan_id):
            if not scan_id in results_dict:
                results_dict[scan_id] = []
            results_dict[scan_id] += results

        mqtt = OpenvasMQTTHandler("foo", add_results)
        mqtt.on_message(
            None,
            mqtt,
            msg,
        )

        self.assertDictEqual(results_dict, {})
        time.sleep(0.3)
        self.assertDictEqual(results_dict, expct_dict)

    def test_json_format(self, mock_client: MagicMock):

        msg = MQTTMessage()
        msg.topic = b"scanner/results"
        msg.payload = b'{"scan_id":"1","type":"foo","host_ip":"127.0.0.1","hostname":"","port":"80","OID":"","value""bar"}'

        def do_nothing(results, scan_id):
            return

        logging.Logger.error = MagicMock()

        mqtt = OpenvasMQTTHandler("foo", do_nothing)
        mqtt.on_message(
            None,
            mqtt,
            msg,
        )

        logging.Logger.error.assert_called_with(  # pylint: disable=no-member
            "Got MQTT message in non-json format."
        )
