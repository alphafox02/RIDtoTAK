"""
MIT License

Copyright (c) 2024 CEMAXECUTER

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import json
import socket
import signal
import sys
import argparse
import threading
import datetime
import ssl
import time
import uuid
import tempfile
import logging
from typing import Dict, Tuple, Optional, Any
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend
from lxml import etree
from threading import Event

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Drone:
    def __init__(self, id: str, lat: float, lon: float, speed: int, vspeed: int, alt: int, height: int, pilot_lat: float, pilot_lon: float, description: str):
        self.id = id
        self.lat = lat
        self.lon = lon
        self.speed = speed
        self.vspeed = vspeed
        self.alt = alt
        self.height = height
        self.pilot_lat = pilot_lat
        self.pilot_lon = pilot_lon
        self.description = description

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "location": {
                "latitude": self.lat,
                "longitude": self.lon
            },
            "speed": {
                "horizontal": self.speed,
                "vertical": self.vspeed
            },
            "altitude": self.alt,
            "height": self.height,
            "pilot_location": {
                "latitude": self.pilot_lat,
                "longitude": self.pilot_lon
            },
            "description": self.description
        }

    def to_cot_xml(self) -> str:
        event = etree.Element('event')
        event.set('version', '2.0')
        event.set('uid', f"drone-{self.id}")
        event.set('type', 'b-m-p-s-m')
        event.set('time', datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.995Z'))
        event.set('start', datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.995Z'))
        event.set('stale', (datetime.datetime.utcnow() + datetime.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S.995Z'))
        event.set('how', 'm-g')

        point = etree.SubElement(event, 'point')
        point.set('lat', str(self.lat))
        point.set('lon', str(self.lon))
        point.set('hae', str(self.alt))
        point.set('ce', '35.0')
        point.set('le', '999999')

        detail = etree.SubElement(event, 'detail')

        contact = etree.SubElement(detail, 'contact')
        contact.set('endpoint', '')
        contact.set('phone', '')
        contact.set('callsign', self.id)

        precisionlocation = etree.SubElement(detail, 'precisionlocation')
        precisionlocation.set('geopointsrc', 'gps')
        precisionlocation.set('altsrc', 'gps')

        remarks = etree.SubElement(detail, 'remarks')
        remarks.text = f"Description: {self.description}, Speed: {self.speed}, VSpeed: {self.vspeed}, Altitude: {self.alt}, Height: {self.height}, Pilot Lat: {self.pilot_lat}, Pilot Lon: {self.pilot_lon}"

        color = etree.SubElement(detail, 'color')
        color.set('argb', '-256')

        usericon = etree.SubElement(detail, 'usericon')
        usericon.set('iconsetpath', '34ae1613-9645-4222-a9d2-e5f243dea2865/Military/UAV_quad.png')

        return etree.tostring(event, pretty_print=True, xml_declaration=True, encoding='UTF-8')

def is_drone_info(entry: Dict[str, Any]) -> bool:
    try:
        layers = entry["_source"]["layers"]
        if "opendroneid" in layers and "opendroneid.message.pack" in layers["opendroneid"]:
            odid_pack = layers["opendroneid"]["opendroneid.message.pack"]
            if "opendroneid.message.basicid" in odid_pack:
                logger.debug("Identified as drone info")
                return True
            else:
                logger.debug("Missing 'opendroneid.message.basicid' in 'opendroneid.message.pack'")
    except KeyError as e:
        logger.error(f"Key error in is_drone_info: {e}")
    return False

def get_drone_id(entry: Dict[str, Any]) -> str:
    try:
        return entry["_source"]["layers"]["opendroneid"]["opendroneid.message.pack"]["opendroneid.message.basicid"]["OpenDroneID.basicID_id_asc"]
    except KeyError as e:
        logger.error(f"Key error in get_drone_id: {e}")
        return "unknown"

def parse_drone_info(entry: Dict[str, Any]) -> Optional[Drone]:
    try:
        odid = entry["_source"]["layers"]["opendroneid"]
        basicid = odid["opendroneid.message.pack"]["opendroneid.message.basicid"]
        description = odid["opendroneid.message.pack"].get("opendroneid.message.selfid", {}).get("OpenDroneID.self_desc", "")
        location = odid["opendroneid.message.pack"].get("opendroneid.message.location", {})
        operator = odid["opendroneid.message.pack"].get("opendroneid.message.operatorid", {})

        return Drone(
            id=basicid.get("OpenDroneID.basicID_id_asc", "unknown"),
            lat=float(location.get("OpenDroneID.loc_lat", 0)) / 1e7,
            lon=float(location.get("OpenDroneID.loc_lon", 0)) / 1e7,
            speed=int(location.get("OpenDroneID.loc_speed", 0)),
            vspeed=int(location.get("OpenDroneID.loc_vspeed", 0)),
            alt=int(location.get("OpenDroneID.loc_geoAlt", 0)),
            height=int(location.get("OpenDroneID.loc_height", 0)),
            pilot_lat=float(operator.get("OpenDroneID.system_lat", 0)) / 1e7,
            pilot_lon=float(operator.get("OpenDroneID.system_lon", 0)) / 1e7,
            description=description
        )
    except KeyError as e:
        logger.error(f"Error parsing drone info: {e}")
        return None

def process_data(data: str, log_location: bool, output_file: Optional[str], tak_host: str, tak_port: int, interval: int, stop_event: Event, last_data_received: Event, tls_context: Optional[ssl.SSLContext] = None, debug: bool = False):
    try:
        if data.strip() == "":
            logger.info("Received empty data, skipping.")
            return
        entry = json.loads(data)
        logger.debug(f"Loaded JSON entry: {entry}")
        last_data_received.set()  # Reset the timeout timer
        if isinstance(entry, list):
            for item in entry:
                process_single_entry(item, log_location, output_file, tak_host, tak_port, interval, stop_event, tls_context, debug)
        else:
            process_single_entry(entry, log_location, output_file, tak_host, tak_port, interval, stop_event, tls_context, debug)
    except json.JSONDecodeError as e:
        logger.error(f"Error processing data: Invalid JSON format. {e}")
    except Exception as e:
        logger.error(f"Error processing data: {e}")

def process_single_entry(entry: Dict[str, Any], log_location: bool, output_file: Optional[str], tak_host: str, tak_port: int, interval: int, stop_event: Event, tls_context: Optional[ssl.SSLContext] = None, debug: bool = False):
    try:
        if is_drone_info(entry):
            drone_id = get_drone_id(entry)
            drone = parse_drone_info(entry)
            if drone:
                if log_location and (drone.lat == 0 and drone.lon == 0):
                    logger.info("Skipping entry without location data.")
                    return
                drone_data = drone.to_dict()
                cot_xml = drone.to_cot_xml()
                if debug:
                    logger.debug(f"CoT XML: {cot_xml}")
                if output_file:
                    with open(output_file, 'a') as f:
                        f.write(json.dumps(drone_data) + '\n')
                send_to_tak(cot_xml, tak_host, tak_port, tls_context, debug)
                time.sleep(interval)
            else:
                logger.info("Drone parsing returned None.")
        else:
            logger.info("Entry is not drone info.")
    except Exception as e:
        logger.error(f"Error processing single entry: {e}")

def send_to_tak(cot_xml: str, tak_host: str, tak_port: int, tls_context: Optional[ssl.SSLContext] = None, debug: bool = False):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Ensure cot_xml is bytes
        if isinstance(cot_xml, str):
            cot_xml = cot_xml.encode('utf-8')
        
        sock.sendto(cot_xml, (tak_host, tak_port))
        sock.close()

        if debug:
            logger.debug(f"Sent CoT to TAK server: {cot_xml}")
    except Exception as e:
        logger.error(f"Error sending to TAK server: {e}")

def signal_handler(sig, frame):
    global stop_event
    logger.info('Exiting and cleaning up...')
    stop_event.set()  # Stop the monitor thread
    sys.exit(0)

def find_complete_json_objects(buffer: str) -> Tuple[list, str]:
    objects = []
    depth = 0
    start = 0
    for i, char in enumerate(buffer):
        if char == '{':
            if depth == 0:
                start = i
            depth += 1
        elif char == '}':
            depth -= 1
            if depth == 0:
                objects.append(buffer[start:i+1])
    return objects, buffer[i+1:] if depth == 0 else buffer

def load_p12_cert(p12_path: str, password: str) -> Tuple[bytes, bytes, Optional[bytes]]:
    with open(p12_path, 'rb') as f:
        p12_data = f.read()
    private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(p12_data, password.encode(), default_backend())
    pkey = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption()
    )
    cert = certificate.public_bytes(Encoding.PEM)
    ca_certs = None
    if additional_certificates:
        ca_certs = b"".join(cert.public_bytes(Encoding.PEM) for cert in additional_certificates)
    return pkey, cert, ca_certs

def main():
    global stop_event
    parser = argparse.ArgumentParser(description='Drone data processing server.')
    parser.add_argument('--log-location', action='store_true', help='Only log entries with location data')
    parser.add_argument('--output-file', type=str, help='File to store drone data')
    parser.add_argument('--input-port', type=int, default=12345, help='Port to accept JSON data streams (default: 12345)')
    parser.add_argument('--input-file', type=str, help='File containing JSON formatted payload of drone data')
    parser.add_argument('--tak-host', type=str, required=True, help='TAK server hostname or IP address')
    parser.add_argument('--tak-port', type=int, required=True, help='TAK server port')
    parser.add_argument('--update-interval', type=int, default=5, help='Update interval in seconds for CoT messages (default: 5)')
    parser.add_argument('--tls-p12', type=str, help='Path to PKCS#12 file for TLS')
    parser.add_argument('--tls-password', type=str, help='Password for PKCS#12 file')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    HOST = '0.0.0.0'
    INPUT_PORT = args.input_port
    TAK_HOST = args.tak_host
    TAK_PORT = args.tak_port
    INTERVAL = args.update_interval

    tls_context = None
    if args.tls_p12 and args.tls_password:
        pkey, cert, ca_certs = load_p12_cert(args.tls_p12, args.tls_password)
        with tempfile.NamedTemporaryFile(delete=False) as pkey_file, \
             tempfile.NamedTemporaryFile(delete=False) as cert_file, \
             tempfile.NamedTemporaryFile(delete=False) as ca_file:
            pkey_file.write(pkey)
            cert_file.write(cert)
            if ca_certs:
                ca_file.write(ca_certs)
        
        tls_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        tls_context.load_cert_chain(certfile=cert_file.name, keyfile=pkey_file.name)
        if ca_certs:
            tls_context.load_verify_locations(cafile=ca_file.name)

    signal.signal(signal.SIGINT, signal_handler)

    stop_event = Event()
    last_data_received = Event()
    last_data_received.set()

    def monitor_data_flow():
        while not stop_event.is_set():
            if not last_data_received.wait(timeout=10):
                logger.info("No data received for 10 seconds, stopping CoT messages.")
                stop_event.set()

    monitor_thread = threading.Thread(target=monitor_data_flow)
    monitor_thread.start()

    if args.input_file:
        logger.info(f"Processing input file: {args.input_file}")
        try:
            with open(args.input_file, 'r') as f:
                data = f.read()
                logger.debug(f"Data from file: {data}")
                process_data(data, args.log_location, args.output_file, TAK_HOST, TAK_PORT, INTERVAL, stop_event, last_data_received, tls_context, args.debug)
        except Exception as e:
            logger.error(f"Error processing input file: {e}")
    else:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.bind((HOST, INPUT_PORT))
                server_socket.listen()
                logger.info(f"Listening for JSON data on {HOST}:{INPUT_PORT}")

                while True:
                    client_socket, client_address = server_socket.accept()
                    logger.info(f"Connected to data source at {client_address}")

                    with client_socket:
                        buffer = ""
                        while not stop_event.is_set():
                            data = client_socket.recv(1024)
                            if not data:
                                break

                            buffer += data.decode('utf-8')
                            
                            # Find and process complete JSON objects
                            objects, buffer = find_complete_json_objects(buffer)
                            for obj in objects:
                                process_data(obj, args.log_location, args.output_file, TAK_HOST, TAK_PORT, INTERVAL, stop_event, last_data_received, tls_context, args.debug)
        except Exception as e:
            logger.error(f"Error in server setup or connection: {e}")

    stop_event.set()
    monitor_thread.join()

if __name__ == "__main__":
    main()
