import subprocess
import logging
import hashlib
import base58
import ecdsa

import os

# Configurations
KEYHUNT_PATH = "./keyhunt"  # Replace with the path to keyhunt binary
RMD160_HASH = "739437bb3dd6d1983e66629c5f08c70e52769371"  # Target rmd160 hash
INITIAL_MIN_RANGE = 73786976294838206464  # Example start of the range
INITIAL_MAX_RANGE = 147573952589676412927  # Example end of the range
NARROW_FACTOR = 0.1  # Factor to narrow the range
FOUND_KEYS_FILE = "found_keys.txt"  # File to store found keys

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")


def run_keyhunt(prefix, range_min, range_max, mode="vanity", start_key=None):
    """
    Run keyhunt to search for the target prefix or perform a sequential search.
    """
    logging.info(f"Running keyhunt in {mode} mode, range: {range_min} - {range_max}, prefix: {prefix}")
    command = [
        KEYHUNT_PATH,
        "-m", mode,
        "-l", "compress",  # Compressed addresses
        "-r", f"{range_min}:{range_max}",
        "-v", prefix,
        "-t", f"{str(input("input CPU theads number: "))}"
    ]
    if start_key:
        command.extend(["-s", start_key])  # Start from the given private key
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        return result.stdout
    except FileNotFoundError:
        logging.error("Keyhunt binary not found. Please check the KEYHUNT_PATH.")
        return None


def extract_matching_key(output):
    """
    Extract a matching private key from keyhunt output.
    """
    for line in output.splitlines():
        if "Found:" in line:
            parts = line.split()
            private_key = parts[1]  # Extract the private key
            logging.info(f"Matching prefix found with private key: {private_key}")
            return private_key
    return None


def private_key_to_rmd160(private_key):
    """
    Convert a private key to its rmd160 hash (Bitcoin hash160).
    """
    # Step 1: Convert private key to 32 bytes (hex string if necessary)
    if isinstance(private_key, str):
        private_key_bytes = bytes.fromhex(private_key)
    else:
        private_key_bytes = private_key

    # Step 2: Generate the public key
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    public_key = b'\x04' + vk.to_string()  # Uncompressed public key format

    # Step 3: Perform SHA256 hashing on the public key
    sha256_hash = hashlib.sha256(public_key).digest()

    # Step 4: Perform RIPEMD-160 hashing on the SHA256 hash
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()

    return ripemd160_hash.hex()


def verify_rmd160(private_key, target_rmd160):
    """
    Verify the private key by checking its rmd160 hash.
    """
    # Step 1: Convert the private key to its rmd160 hash
    generated_rmd160 = private_key_to_rmd160(private_key)

    # Step 2: Compare the generated rmd160 hash with the target hash
    return generated_rmd160 == target_rmd160


def main():
    # Initial search range
    range_min = INITIAL_MIN_RANGE
    range_max = INITIAL_MAX_RANGE
    lengh = int(input("Input Prefix Lenght: "))
    prefix = RMD160_HASH[:lengh]  # Use the first few characters of rmd160 as prefix

    while range_max - range_min > 1:
        # Search for matching prefix
        output = run_keyhunt(prefix, range_min, range_max)
        if not output:
            logging.error("Keyhunt failed to run.")
            break

        private_key = extract_matching_key(output)
        if private_key:
            # Save found private key
            with open(FOUND_KEYS_FILE, "a") as f:
                f.write(f"{private_key}\n")

            # Verify the private key
            if verify_rmd160(private_key, RMD160_HASH):
                logging.info(f"Success! Found private key: {private_key}")
                break

            # Narrow the search range
            logging.info("Narrowing the search range.")
            range_min = int(private_key, 16)  # Use the found private key as the new min range
            range_max = int(range_min + (range_max - range_min) * NARROW_FACTOR)

            # Sequential search
            run_keyhunt(prefix, range_min, range_max, mode="sequential", start_key=private_key)
        else:
            logging.info("No prefix matches found in this range. Expanding search.")
            range_min = int(range_min + (range_max - range_min) * NARROW_FACTOR)

    logging.info("Search completed.")


if __name__ == "__main__":
    main()
