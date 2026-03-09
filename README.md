# Cover Channel in TLS 1.3
This project demonstrates a covert communication channel embedded within the TLS 1.3 protocol using the CCCC scheme. It allows two parties to exchange hidden messages while appearing to perform a normal TLS 1.3 session to an auditor.

The implementation is a proof-of-concept and includes simplified TLS handshake, modified EdDSA for IV hiding, and core cryptographic operations in GF(2¹²⁸).

## Requirements
Python 3.8+
pycryptodome
cryptography

Install dependencies:
```bash
pip install pycryptodome cryptography
```

## File Descriptions
| File | Description |
| --- | --- |
| `auditor.py` | Simulates a mandatory auditor (censor) who intercepts the communication and attempts to decrypt the ciphertext using the auditable key. It only sees the fake plaintext. |
| `const_algorithm.py` | Provides helper functions for the Const algorithm to compute intermediate values and construct collision ciphertexts. |
| `cccc.py` | Core implementation of the CCCC algorithms: const (construct collision ciphertext), embed (generate IV from hidden message), extract (recover hidden message), audit (auditor decryption), and collision verification. |
| `eddsa_modified.py` | Modified EdDSA signature scheme that embeds the IV into the signature. The IV can later be extracted by the receiver who knows the private key. |
| `gf128.py` | Provides arithmetic operations in the finite field GF(2¹²⁸) (addition, multiplication, inversion, etc.) used for GHASH computation and linear equation solving. |
| `main.py` | Main entry point that starts a server thread and runs the client to demonstrate the full covert communication flow. |
| `solve_mat.py` | Linear equation solver for GF(2¹²⁸). It solves the 2×2 system required to obtain a collision ciphertext (simplified version). |
| `tls13_client.py` | TLS 1.3 client implementation. Performs a simplified handshake, constructs the collision ciphertext, embeds the hidden message, and sends it in an application data record along with the modified signature. |
| `tls13_server.py` | TLS 1.3 server implementation. Completes the handshake, receives the application data, extracts the IV from the signature, and recovers the hidden message using the extraction key. |

## Usage
Run the demonstration:
```bash
python main.py
```

The script will:
Start a TLS 1.3 server thread.
Start a TLS 1.3 client thread.
Perform a simplified handshake.
Client sends a hidden message embedded in a collision ciphertext.
Server extracts the covert message.
An auditor intercepts and sees only overt data.
