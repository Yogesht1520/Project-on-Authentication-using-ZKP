import hashlib
import random

def sha256_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

class ZeroKnowledgeProof:
    def __init__(self, secret):
        self.secret = secret
        self.commitment = None

    def create_commitment(self):
        self.random_value = str(random.randint(1, 1000000))
        self.commitment = sha256_hash(self.random_value)
        return self.commitment

    def create_challenge(self):
        self.challenge = str(random.randint(1, 1000000))
        return self.challenge

    def compute_response(self):
        combined = self.random_value + self.secret + self.challenge
        self.response = sha256_hash(combined)
        return self.response

    def verify(self, prover_response, prover_commitment):
        recomputed_combined = self.random_value + self.secret + self.challenge
        recomputed_response = sha256_hash(recomputed_combined)
        if prover_response == recomputed_response and prover_commitment == self.commitment:
            return True
        else:
            return False

if __name__ == "__main__":
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    secret = password

    zk_proof = ZeroKnowledgeProof(secret)

    commitment = zk_proof.create_commitment()
    print(f"\n{username}'s commitment: {commitment}")

    challenge = zk_proof.create_challenge()
    print(f"Verifier's challenge: {challenge}")

    response = zk_proof.compute_response()
    print(f"{username}'s response: {response}")

    verification_result = zk_proof.verify(response, commitment)
    if verification_result:
        print("\nVerification successful. Zero-Knowledge Proof passed!")
    else:
        print("\nVerification failed. Zero-Knowledge Proof failed.")
