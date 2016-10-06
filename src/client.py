from core import Core
from petlib.ec import EcGroup, EcPt
from petlib import pack
from random import randint
from crypto import Crypto
import time
import msgpack
import json
import base64
import sys
import threading

class Client(Core):

    def __init__(self):
        super(Client, self).__init__()
        self.id = randint(1000,100000)
        self.logger.info("Running in Client mode")
        self.public_keys = []
        self.client_keypair = []

    def generate_readings(self):
        cur_thread = threading.current_thread()
        self.logger.debug("Processing generate_readings() in thread: {}".format(cur_thread.name))
        crypto = Crypto()
        params = crypto.setup()
        while True:
            reading = randint(0,100)
            print(time.ctime(),reading)
            encrypted_reading = crypto.encrypt(params, self.client_keypair[1], reading)
            b64_reading = base64.b64encode(pack.encode(encrypted_reading))
            json_str = {"ID": self.id, "IP": self.get_ip(), "OPERATION": "READINGS", "reading": b64_reading}
            self.send(self.nodes[0], json.dumps(json_str))
            time.sleep(5)

    def add_public_key(self,key):
        self.public_keys.append(key)

    def get_public_keys(self, key):
        return self.public_keys

    def setup(self):
        self._callbacks["DECRYPT_GROUP_MSG"] = self._decrypt_group_message
        self.get_nodes()
        self.logger.debug("Generating keypairs...")
        crypto = Crypto()
        params = crypto.setup()
        priv, pub = crypto.key_gen(params)
        self.client_keypair.extend([priv, pub])
        self.add_public_key(pub)

    def start(self):
        b64_enc = base64.b64encode(pack.encode(self.client_keypair[1]))
        self.send(self.nodes[0], json.dumps({"ID":str(self.id), "IP":self.get_ip(), "OPERATION": "GROUP_KEY_CREATE", "PUB":b64_enc}))
        self.logger.debug("Public Key has been sent.")
        # #readings_thread = threading.Thread(target=self.generate_readings)
        # listening_thread = threading.Thread(target=self.listen)
        # try:
        #     listening_thread.start()
        #     #readings_thread.start()
        # except (KeyboardInterrupt, SystemExit):
        #     cleanup_stop_thread();
        #     sys.exit()

        # self.generate_readings()

    def _decrypt_group_message(self, json_decoded):
        pass

'''
c = Client()
c.listen()
for x in clients:
    if(x == c.get_ip):
        c.id = id
        id += 1

crypto = Crypto()
params = crypto.setup()
priv, pub = crypto.key_gen(params)

b64_enc = base64.b64encode(pack.encode(pub))
print b64_enc

c.send("localhost", json.dumps({"id":str(c.id), "IP":c.get_ip(), "operation": "key", "pub":b64_enc}))

while True:
  c.generate_readings()
  time.sleep(2)
'''

