import hashlib
import random
import tkinter as tk
from tkinter import messagebox

def sha256_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

class ZeroKnowledgeProver:
    def __init__(self, secret):
        self.secret = secret

    def create_commitment(self):
        self.random_value = str(random.randint(1, 1000000))  # Random value for commitment
        self.commitment = sha256_hash(self.random_value)  # Commitment hash
        return self.commitment

    def compute_response(self, challenge):
        combined = self.random_value + self.secret + challenge  # Combine for response
        self.response = sha256_hash(combined)  # Calculate response
        return self.response

class ZeroKnowledgeVerifier:
    def __init__(self, secret_hash):
        self.secret_hash = secret_hash
        self.challenge = None

    def create_challenge(self):
        self.challenge = str(random.randint(1, 1000000))  # Random challenge
        return self.challenge

    def verify(self, prover_response, prover_commitment, random_value, secret):
        recombined_value = random_value + secret + self.challenge  # Recombine for expected response
        recombined_response = sha256_hash(recombined_value)  # Hash the recombined value
        return (
            prover_response == recombined_response and 
            prover_commitment == sha256_hash(random_value)  # Check commitment match
        )

class ZKPApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Zero-Knowledge Proof Authentication")

        self.stored_username = "user123"  # Example username
        self.stored_password_hash = sha256_hash("my_secret_password")  # Example hashed password

        self.label_username = tk.Label(root, text="Username:")
        self.label_username.pack(pady=5)

        self.entry_username = tk.Entry(root)
        self.entry_username.pack(pady=5)

        self.label_password = tk.Label(root, text="Password:")
        self.label_password.pack(pady=5)

        self.entry_password = tk.Entry(root, show="*")
        self.entry_password.pack(pady=5)

        self.button_authenticate = tk.Button(root, text="Authenticate", command=self.authenticate)
        self.button_authenticate.pack(pady=20)

    def authenticate(self):
        username = self.entry_username.get()
        password = self.entry_password.get()

        if not username or not password:
            messagebox.showerror("Input Error", "Please enter both username and password.")
            return

        # Check if the username matches the stored username
        if username != self.stored_username:
            messagebox.showerror("Verification Result", "Invalid username.")
            return

        zk_prover = ZeroKnowledgeProver(password)
        commitment = zk_prover.create_commitment()

        # Create a verifier instance with the hashed stored password
        zk_verifier = ZeroKnowledgeVerifier(self.stored_password_hash)
        challenge = zk_verifier.create_challenge()
        response = zk_prover.compute_response(challenge)

        # Verify using the user's password
        if zk_verifier.verify(response, commitment, zk_prover.random_value, password):
            messagebox.showinfo("Verification Result", "Verification successful! Zero-Knowledge Proof passed.")
        else:
            messagebox.showerror("Verification Result", "Verification failed! Zero-Knowledge Proof failed.")

if __name__ == "__main__":
    root = tk.Tk()
    app = ZKPApp(root)
    root.mainloop()
