import logging
import threading

from unittest.case import TestCase
from unittest.mock import MagicMock, patch

from paho.mqtt.client import MQTTMessage

from ospd_openvas.mqtt import MQTTHandler, OpenvasMQTTHandler


class TestMQTT(TestCase):
    @patch('paho.mqtt.client.Client', autospec=True)
    def test_on_message_not_implemented(self, _mock_client: MagicMock):
        mqtt = MQTTHandler("foo", "bar")

        with self.assertRaises(NotImplementedError):
            mqtt.on_message(None, None, None)

    @patch('paho.mqtt.client.Client', autospec=True)
    def test_publish_message(self, _mock_client: MagicMock):
        mqtt = MQTTHandler("foo", "bar")

        logging.Logger.debug = MagicMock()

        mqtt.publish("foo/bar", "test123")

        logging.Logger.debug.assert_called_with(  # pylint: disable=no-member
            'Published message on topic %s.', "foo/bar"
        )

    @patch('paho.mqtt.client.Client', autospec=True)
    def test_insert_results(self, _mock_client: MagicMock):
        def start(self):
            self.function(*self.args, **self.kwargs)

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
        msg.payload = (
            b'{"scan_id":"1","type":"foo","host_ip":'
            b'"127.0.0.1","hostname":"","port":"80","OID":"","value":"bar"}'
        )

        def add_results(results, scan_id):
            if not scan_id in results_dict:
                results_dict[scan_id] = []
            results_dict[scan_id] += results

        with patch.object(threading.Timer, 'start', start):
            mqtt = OpenvasMQTTHandler("foo", add_results)
            mqtt.on_message(
                None,
                mqtt,
                msg,
            )

            self.assertDictEqual(results_dict, expct_dict)

    @patch('paho.mqtt.client.Client', autospec=True)
    def test_json_format(self, _mock_client: MagicMock):

        msg = MQTTMessage()
        msg.topic = b"scanner/results"
        msg.payload = (
            b'{"scan_id":"1","type":"foo","host_ip":'
            b'"127.0.0.1","hostname":"","port":"80","OID":"","value""bar"}'
        )

        def do_nothing(_results, _scan_id):
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
