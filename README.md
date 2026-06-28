# COMP3221 Assignment 2: Blockchain

### Instructions

1. This program is designed for Python 3.11+, or the default Python 3 enviroment of Ed.
2. Run `./Build.sh` to install the required libraries: `PyNaCl` and `ed25519`. PyNaCl version 1.6.2
3. Start each node using the `Run.sh` script:
`./Run.sh <port> <nodes.txt>`

### Implementation

This program implements a peer to peer blockchain network.

* **Networking:** Every node maintains long lived TCP connections to all other peers in the network.
* **Consensus:** Nodes use a round based protocol to agree on the next block. If a peer does not respond within two seconds, it is marked as crashed.
* **Validation:** All transactions are validated for correct Ed25519 signatures and strict nonce ordering as required by the assignment spec.

### Integrity

I used the PyNaCl library version 1.6.2 for digital signature verification. I used Gemini by Alphabet (2026), models 3.1 Pro and 3.5 Flash to assist in debugging complex thread synchronisation, network socket logic, and autograder timeout issues. Also used it to help write this document.