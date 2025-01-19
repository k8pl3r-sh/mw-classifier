import redis
from utils.logger import Log
import numpy as np
from utils.config import Config

class RedisStorage:
    def __init__(self):
        self.config = Config().get()
        self.r = redis.Redis(host=self.config['redis']['host'], port=self.config['redis']['port'], db=self.config['redis']['db'])
        self.log = Log("RedisStorage")


    def store_minhash_signature(self, malware_id: str, minhash_signature):
        # Store the MinHash signature in Redis using a unique malware ID
        key = f'malware:{malware_id}:minhash'
        self.r.set(key, minhash_signature.hashvalues.tobytes())
        self.log.debug(f'Stored MinHash signature for {malware_id} in Redis.')

    def get_minhash_signature(self, malware_id: str):
        # Retrieve the MinHash signature from Redis
        key = f'malware:{malware_id}:minhash'
        signature_bytes = self.r.get(key)
        if signature_bytes:
            return np.frombuffer(signature_bytes, dtype=np.uint32)  # Adjust dtype as needed
        self.log.warn(f'MinHash signature for {malware_id} not found in Redis.')
        return None
