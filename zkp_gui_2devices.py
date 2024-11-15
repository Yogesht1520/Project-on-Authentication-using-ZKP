import hashlib
import random
import socket
import tkinter as tk
from tkinter import messagebox

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

class ZKPApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Zero-Knowledge Proof Authentication")
        
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
        
        zk_prover = ZeroKnowledgeProver(password)
        commitment = zk_prover.create_commitment()

        try:
            server_ip = '192.168.1.10'  # Replace with the actual IP address of the verifier
            server_port = 12345  # Replace with the actual port number
            
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((server_ip, server_port))

            client_socket.send(commitment.encode())
            client_socket.send(zk_prover.random_value.encode())

            challenge = client_socket.recv(1024).decode()
            response = zk_prover.compute_response(challenge)

            client_socket.send(response.encode())
            client_socket.send(password.encode())  # Send the password for verification

            verification_result = client_socket.recv(1024).decode()
            messagebox.showinfo("Verification Result", verification_result)

            client_socket.close()

        except Exception as e:
            messagebox.showerror("Connection Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = ZKPApp(root)
    root.mainloop()
