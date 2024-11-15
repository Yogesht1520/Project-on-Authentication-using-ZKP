import hashlib
import random

# Helper function to compute SHA-256 hash
def sha256_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

# Zero-Knowledge Proof Setup
class ZeroKnowledgeProof:
    def __init__(self, secret):
        self.secret = secret  # The secret known only by the prover
        self.commitment = None

    # Step 1: Prover creates a random commitment
    def create_commitment(self):
        self.random_value = str(random.randint(1, 1000000))  # Random value for commitment
        self.commitment = sha256_hash(self.random_value)
        return self.commitment

    # Step 2: Verifier issues a challenge
    def create_challenge(self):
        self.challenge = str(random.randint(1, 1000000))
        return self.challenge

    # Step 3: Prover responds to the challenge using the secret
    def compute_response(self):
        combined = self.random_value + self.secret + self.challenge
        self.response = sha256_hash(combined)
        return self.response

    # Step 4: Verifier verifies the response
    def verify(self, prover_response, prover_commitment):
        # Recompute commitment and response
        recomputed_combined = self.random_value + self.secret + self.challenge
        recomputed_response = sha256_hash(recomputed_combined)

        # Check if responses match
        if prover_response == recomputed_response and prover_commitment == self.commitment:
            return True
        else:
            return False

# Example usage:
if __name__ == "__main__":
    # Step 1: Prover has a secret (e.g., password or private key)
    secret = "my_secret_password"

    # Initialize the Zero-Knowledge Proof system
    zk_proof = ZeroKnowledgeProof(secret)

    # Step 2: Prover creates a commitment and sends it to the verifier
    commitment = zk_proof.create_commitment()
    print(f"Prover's commitment: {commitment}")

    # Step 3: Verifier creates a challenge and sends it to the prover
    challenge = zk_proof.create_challenge()
    print(f"Verifier's challenge: {challenge}")

    # Step 4: Prover computes a response based on the challenge and sends it to the verifier
    response = zk_proof.compute_response()
    print(f"Prover's response: {response}")

    # Step 5: Verifier verifies the prover's response
    verification_result = zk_proof.verify(response, commitment)
    if verification_result:
        print("Verification successful. Zero-Knowledge Proof passed!")
    else:
        print("Verification failed. Zero-Knowledge Proof failed.")
