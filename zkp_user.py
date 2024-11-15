import hashlib
import random
import socket

def sha256_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

class ZeroKnowledgeProver:
    def __init__(self, secret):
        self.secret = secret

    def create_commitment(self):
        self.random_value = str(random.randint(1, 1000000))
        self.commitment = sha256_hash(self.random_value)
        return self.commitment

    def compute_response(self, challenge):
        combined = self.random_value + self.secret + challenge
        self.response = sha256_hash(combined)
        return self.response

if __name__ == "__main__":
    prover_password = "my_secret_password"
    zk_prover = ZeroKnowledgeProver(prover_password)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('VERIFIER_IP_ADDRESS', 12345))  # Replace with verifier's IP address

    commitment = zk_prover.create_commitment()
    client_socket.send(commitment.encode())
    client_socket.send(zk_prover.random_value.encode())

    challenge = client_socket.recv(1024).decode()
    response = zk_prover.compute_response(challenge)
    client_socket.send(response.encode())
    client_socket.send(prover_password.encode())

    verification_result = client_socket.recv(1024).decode()
    print(verification_result)

    client_socket.close()
