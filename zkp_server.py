import hashlib
import random
import socket

def sha256_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

class ZeroKnowledgeVerifier:
    def __init__(self, secret_hash):
        self.secret_hash = secret_hash

    def create_challenge(self):
        self.challenge = str(random.randint(1, 1000000))
        return self.challenge

    def verify(self, prover_response, prover_commitment, random_value, secret):
        recombined_value = random_value + secret + self.challenge
        recombined_response = sha256_hash(recombined_value)
        if prover_response == recombined_response and prover_commitment == sha256_hash(random_value):
            return True
        return False

if __name__ == "__main__":
    secret_password = "my_secret_password"
    secret_password_hash = sha256_hash(secret_password)

    zk_verifier = ZeroKnowledgeVerifier(secret_password_hash)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 12345))  # Verifier listens on port 12345
    server_socket.listen(1)
    print("Verifier is waiting for connection...")

    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    commitment = conn.recv(1024).decode()
    random_value = conn.recv(1024).decode()

    challenge = zk_verifier.create_challenge()
    conn.send(challenge.encode())

    prover_response = conn.recv(1024).decode()
    prover_secret = conn.recv(1024).decode()

    if zk_verifier.verify(prover_response, commitment, random_value, prover_secret):
        print("Verification successful. Zero-Knowledge Proof passed!")
        conn.send("Verification Successful".encode())
    else:
        print("Verification failed. Zero-Knowledge Proof failed.")
        conn.send("Verification Failed".encode())

    conn.close()
