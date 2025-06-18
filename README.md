# crypto-signature-analyzer
Analyzes digital signatures (e.g., ECDSA, EdDSA) to detect common vulnerabilities, such as biased nonces or insufficient randomness in signature generation. It checks for patterns indicative of key compromise or implementation flaws by analyzing collections of signatures from the same key. - Focused on Basic cryptographic operations

## Install
`git clone https://github.com/ShadowGuardAI/crypto-signature-analyzer`

## Usage
`./crypto-signature-analyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-f`: No description provided
- `-s`: JSON string containing list of signatures
- `-k`: Path to the PEM-encoded public key file.
- `-m`: Message associated with the signature.
- `-sig`: No description provided
- `-alg`: No description provided
- `-v`: Enable verbose output for debugging.

## License
Copyright (c) ShadowGuardAI
