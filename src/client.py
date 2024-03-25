import netifaces
import threading
import time
import json
import base64
import sys
import msgpack
from random import randint
from petlib.ec import EcGroup, EcPt
from petlib import pack
from crypto import Crypto
from core import Core

class Client(Core):

    def __init__(self):
        super(Client, self).__init__()
        self.id = randint(1000, 100000)
        self.logger.info("Running in Client mode")
        self.ip = self.get_interface_ip('eth1')  # Get IP address of 'eth1' interface
        self.public_keys = []
        self.client_keypair = []
        self.group_key = []

    def get_interface_ip(self, interface):
        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addresses:
            return addresses[netifaces.AF_INET][0]['addr']
        else:
            raise ValueError("Interface '{}' does not have an IPv4 address".format(interface))

    def generate_readings(self):
        self.logger.debug('generate_readings starting')
        event_is_set = self.e.wait()
        self.logger.debug('event set: %s', event_is_set)

        if len(self.group_key) != 0:
            crypto = Crypto()
            params = crypto.setup()
            while True:
                reading = randint(0, 100)
                print(time.ctime(), reading)
                encrypted_reading = crypto.encrypt(params, self.group_key[0], reading)
                b64_reading = base64.b64encode(pack.encode(encrypted_reading))
                json_str = {"ID": self.id, "OPERATION": "READINGS", "reading": b64_reading}
                self.send(self.nodes[0], json.dumps(json_str))
                time.sleep(5)

    def add_public_key(self, key):
        self.public_keys.append(key)

    def setup(self):
        self._callbacks["DECRYPT_GROUP_MSG"] = self._decrypt_group_message
        self._callbacks["RECEIVE_GROUP_KEY"] = self._receive_group_key
        self.get_nodes()
        self.logger.debug("Generating keypairs...")
        self.crypto = Crypto()
        self.params = self.crypto.setup()
        self.priv, self.pub = self.crypto.key_gen(self.params)
        self.client_keypair.extend([self.priv, self.pub])
        self.add_public_key(self.pub)

    def start(self):
        b64_enc = base64.b64encode(pack.encode(self.client_keypair[1]))
        self.send(self.nodes[0], json.dumps({"ID": str(self.id), "OPERATION": "GROUP_KEY_CREATE", "PUB": b64_enc}))
        print("Public Key has been sent.")
        self.e = threading.Event()
        readings_thread = threading.Thread(target=self.generate_readings)
        listening_thread = threading.Thread(target=self.listen)
        readings_thread.daemon = True
        listening_thread.daemon = True
        try:
            listening_thread.start()
            readings_thread.start()
        except (KeyboardInterrupt, SystemExit):
            cleanup_stop_thread()
            sys.exit()
        else:
            pass

    def _decrypt_group_message(self, json_decoded, ip):
        print("Decrypting group message...")
        t1 = self.crypto.partialDecrypt(self.params, self.priv, pack.decode(base64.b64decode(json_decoded['reading'])), False)
        if self.ip == self.nodes[-1]:
            self.send(self.nodes[0], json.dumps({"ID": json_decoded['ID'], "OPERATION": "DECRYPT_GROUP_FINAL", "PUB": base64.b64encode(pack.encode(self.group_key)), "reading": base64.b64encode(pack.encode(t1))}))
        else:
            for i in range(len(self.nodes)):
                if self.ip == self.nodes[i]:
                    self.send(self.nodes[i + 1], json.dumps({"ID": json_decoded['ID'], "OPERATION": "DECRYPT_GROUP_MSG", "PUB": base64.b64encode(pack.encode(self.group_key)), "reading": base64.b64encode(pack.encode(t1))}))

    def _receive_group_key(self, json_decoded, ip):
        self.group_key.append(pack.decode(base64.b64decode(json_decoded['PUB'])))
        self.e.set()

if __name__ == "__main__":
    client = Client()
    client.setup()
    client.start()
