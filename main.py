import argparse
import logging
import os
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import binascii

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Analyzes digital signatures for vulnerabilities.")
    parser.add_argument("-f", "--file", dest="signature_file", help="Path to the file containing signatures (JSON format). Each signature should include 'signature', 'message', and 'public_key' (PEM format) keys.", required=False)
    parser.add_argument("-s", "--signatures", dest="signatures_json", help="JSON string containing list of signatures", required=False)
    parser.add_argument("-k", "--public_key", dest="public_key", help="Path to the PEM-encoded public key file.", required=False)
    parser.add_argument("-m", "--message", dest="message", help="Message associated with the signature.", required=False)
    parser.add_argument("-sig", "--signature", dest="signature", help="Signature to verify (hex encoded).", required=False)
    parser.add_argument("-alg", "--algorithm", dest="algorithm", help="Signature Algorithm (ecdsa or eddsa). Default: ecdsa", default="ecdsa", choices=['ecdsa', 'eddsa'], required=False)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output for debugging.")

    return parser.parse_args()


def load_signatures_from_file(file_path):
    """
    Loads signatures from a JSON file.
    Args:
        file_path (str): Path to the JSON file.
    Returns:
        list: A list of signature dictionaries.
    """
    try:
        with open(file_path, 'r') as f:
            signatures = json.load(f)
        return signatures
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return None
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON format in file: {file_path}")
        return None
    except Exception as e:
        logging.error(f"Error loading signatures from file: {e}")
        return None


def analyze_ecdsa_signatures(signatures):
    """
    Analyzes ECDSA signatures for common vulnerabilities (e.g., nonce reuse).
    Args:
        signatures (list): A list of signature dictionaries, each containing 'signature', 'message', and 'public_key'.
    Returns:
        dict: A dictionary of analysis results.
    """
    results = {"nonce_reuse": False, "signature_count": len(signatures)}
    nonces = set()
    for signature_data in signatures:
        try:
            signature = signature_data['signature']
            # Assuming signature is in DER format (r, s)
            r = int(signature[:len(signature)//2], 16)
            nonces.add(r)

        except Exception as e:
            logging.warning(f"Error processing signature: {e}")
            continue

    if len(nonces) < len(signatures):
        results["nonce_reuse"] = True
        logging.warning("Potential nonce reuse detected in ECDSA signatures.")

    return results


def verify_signature(public_key_pem, message, signature, algorithm="ecdsa"):
    """
    Verifies a digital signature against a public key and message.

    Args:
        public_key_pem (str): PEM-encoded public key.
        message (bytes): Message that was signed (bytes).
        signature (bytes): The signature to verify (bytes).  Can be hex encoded
        algorithm (str, optional): The signature algorithm (ecdsa or eddsa). Defaults to "ecdsa".

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )

        if algorithm == "ecdsa":
             public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256()) # Assuming SHA256
            )
             return True
        elif algorithm == "eddsa":
            public_key.verify(signature, message)
            return True
        else:
            logging.error(f"Unsupported algorithm: {algorithm}")
            return False

    except InvalidSignature:
        logging.warning("Signature verification failed.")
        return False
    except Exception as e:
        logging.error(f"Error during signature verification: {e}")
        return False


def main():
    """
    Main function to parse arguments, load signatures, analyze them, and output results.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    signatures = []

    # Load signatures from file if specified
    if args.signature_file:
        signatures = load_signatures_from_file(args.signature_file)
        if signatures is None:
            return  # Exit if loading fails

    # Load signatures from JSON string if specified
    elif args.signatures_json:
        try:
            signatures = json.loads(args.signatures_json)
        except json.JSONDecodeError:
            logging.error("Invalid JSON format in signatures string.")
            return
        except Exception as e:
             logging.error(f"Error parsing signatures JSON: {e}")
             return

    # If signature verification is requested
    if args.public_key and args.message and args.signature:
        try:
            with open(args.public_key, 'r') as f:
                public_key_pem = f.read()

            message = args.message.encode('utf-8')
            signature = binascii.unhexlify(args.signature)
            is_valid = verify_signature(public_key_pem, message, signature, args.algorithm)

            if is_valid:
                print("Signature is VALID.")
            else:
                print("Signature is INVALID.")

        except FileNotFoundError:
            logging.error(f"Public key file not found: {args.public_key}")
            return
        except Exception as e:
            logging.error(f"Error during signature verification: {e}")
            return

    elif signatures:
        if args.algorithm == "ecdsa":
            analysis_results = analyze_ecdsa_signatures(signatures)
            print(json.dumps(analysis_results, indent=4))
        else:
            print("Analysis only available for ECDSA signatures.")
    else:
        print("No signatures provided for analysis. Use -f/--file or -s/--signatures.")


if __name__ == "__main__":
    main()