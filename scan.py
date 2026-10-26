import json
import nmap
import time
import sys
import os
import yaml
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Tuple
from datetime import datetime, timedelta
import redis


logging.getLogger().setLevel(logging.INFO)

REDIS_KEY = "DeviceScanner:People"


class ApiHandler(BaseHTTPRequestHandler):
    scanner = None  # set by DeviceScanner._start_api

    def do_GET(self):
        if self.path != "/people":
            self.send_error(404)
            return

        body = json.dumps(self.scanner.online).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        logging.debug(format % args)


class DeviceScanner:
    def __init__(self, config: dict):
        self.last_seen = {}  # <mac-address: str>: <last-seen: datetime>
        self.online = []  # snapshot of last_seen keys, read by the api thread

        # mac address config
        self.people = config.get("people", {})
        self.reverse_mapping = {}
        for person, person_addresses in self.people.items():
            for known_address in person_addresses:
                self.reverse_mapping[known_address] = person

        # network settings
        self.hosts = config.get("hosts", "192.168.0.0/24")
        self.interval = config.get("interval", 10)  # 10 seconds
        self.last_seen_time = config.get("last_seen", 5 * 60)  # 5 minutes

        # redis persistance
        self.redis_enable = config.get("redis_enable", False)
        if self.redis_enable:
            try:
                redis_host = config["redis_host"]
                redis_port = config["redis_port"]
                self._redis = redis.Redis(host=redis_host, port=redis_port, db=0)
            except KeyError:
                logging.error("redis_host or redis_port are not set")
                self.redis_enable = False

        # file persistance
        self.file_enable = config.get("file_enable", False)
        if self.file_enable:
            try:
                self.file_path = config["file_path"]
            except KeyError:
                logging.error("file_path is not set")
                self.file_enable = False

        # api
        self.api_enable = config.get("api_enable", False)
        if self.api_enable:
            try:
                self.api_host = config["api_host"]
                self.api_port = config["api_port"]
            except KeyError:
                logging.error("api_host or api_port are not set")
                self.api_enable = False

        # address logging
        self.log_enable = config.get("log_enable", False)
        if self.log_enable:
            try:
                self.log_path = config["log_path"]
            except KeyError:
                logging.error("log_path is not set")
                self.log_enable = False

    def scan(self) -> Tuple[list, list]:
        mac_addresses = []
        try:
            mac_addresses = self._raw_scan()
        except Exception as e:
            logging.warning(e)

        if self.log_enable:
            self._log(mac_addresses)

        names, unknown = self._translate_addresses(mac_addresses)
        return names, unknown

    def start(self):
        if self.api_enable:
            self._start_api()

        logging.info("Start scanning")

        while True:
            names, unknown = self.scan()
            logging.info(f"{datetime.now()}: 🪪 {names}, 📱 {unknown}")

            self._update_last_seen(names)
            self.online = list(self.last_seen.keys())

            if self.redis_enable:
                self._save_redis()

            if self.file_enable:
                self._save_file()

            time.sleep(self.interval)

    def _raw_scan(self) -> list:
        nm = nmap.PortScanner()
        raw_scan_result = nm.scan(
            hosts=self.hosts, arguments="-sn --max-parallelism 100"
        )

        mac_addresses = list()
        scan_result = raw_scan_result.get("scan", dict())
        for _, info in scan_result.items():
            addresses = info["addresses"]
            if "mac" in addresses:
                mac_address = addresses["mac"]
                mac_addresses.append(mac_address)
        return mac_addresses

    def _translate_addresses(self, addresses: list) -> Tuple[list, list]:
        names, unknown = set(), set()
        for address in addresses:
            if address in self.reverse_mapping:
                name = self.reverse_mapping[address]
                names.add(name)
            else:
                unknown.add(address)
        return list(names), list(unknown)

    def _update_last_seen(self, people: list):
        # update currently there
        t = datetime.now()
        for person in people:
            self.last_seen[person] = t

        # remove old entries
        last_seen_ago = datetime.now() - timedelta(seconds=self.last_seen_time)
        to_remove = []
        for person, last_seen in self.last_seen.items():
            if last_seen < last_seen_ago:
                to_remove.append(person)
        for person in to_remove:
            del self.last_seen[person]

    def _save_redis(self):
        tracked = list(self.last_seen.keys())

        try:
            obj = json.dumps(tracked)
            self._redis.set(REDIS_KEY, obj)
        except Exception as e:
            logging.warning(f"Could not save to Redis: {e}")

    def _save_file(self):
        tracked = self.last_seen.keys()

        with open(self.file_path, "w") as f:
            tracked = self.last_seen.keys()
            f.write("\n".join(tracked))
            f.write("\n")

    def _start_api(self):
        ApiHandler.scanner = self
        server = ThreadingHTTPServer((self.api_host, self.api_port), ApiHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        logging.info(f"API listening on {self.api_host}:{self.api_port}")

    def _log(self, addresses: list):
        with open(self.log_path, "a") as f:
            f.write(str(datetime.now()))
            f.write(";")
            f.write(";".join(addresses))
            f.write("\n")


if __name__ == "__main__":
    try:
        config_path = os.environ["DEVICE_SCANNER_CONFIG"]
    except KeyError:
        logging.error("DEVICE_SCANNER_CONFIG is not set")
        sys.exit(1)

    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
    except yaml.YAMLError as e:
        logging.error(f"Config {config_path} does not exist or is invalid")
        sys.exit(1)

    dt = DeviceScanner(config)
    dt.start()
