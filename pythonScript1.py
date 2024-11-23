import subprocess
import logging
import hashlib
import ecdsa

# Configurations
KEYHUNT_PATH = "./keyhunt"  # Path to keyhunt binary
RMD160_HASH = "739437bb3dd6d1983e66629c5f08c70e52769371"  # Target rmd160 hash
INITIAL_MIN_RANGE = 73786976294838206464  # Example start of the range
INITIAL_MAX_RANGE = 147573952589676412927  # Example end of the range
NARROW_FACTOR = 0.1  # Factor to narrow the range
FOUND_KEYS_FILE = "found_keys.txt"  # File to store found keys
THREADS = 4  # Number of CPU threads for keyhunt

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
        "-f", "unsolvedpuzzles.rmd",
        "-r", f"{range_min}:{range_max}",
        "-v", prefix,
        "-t", str(THREADS)
    ]
    if start_key:
        command.extend(["-s", start_key])  # Start from the given private key
    process = subprocess.Popen(command, stdout=subprocess.PIPE, text=True)
    return process


def process_keyhunt_output(process, prefix):
    """
    Listen to keyhunt output and extract the first matching prefix.
    """
    logging.info("Listening to keyhunt output...")
    for line in iter(process.stdout.readline, ''):
        logging.info(line.strip())
        if "Found:" in line:
            parts = line.split()
            private_key = parts[1]  # Extract the private key
            logging.info(f"Prefix matched with private key: {private_key}")
            return private_key
    return None


def private_key_to_rmd160(private_key):
    """
    Convert a private key to its rmd160 hash (Bitcoin hash160).
    """
    # Step 1: Convert private key to 32 bytes
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
    generated_rmd160 = private_key_to_rmd160(private_key)
    return generated_rmd160 == target_rmd160


def main():
    range_min = INITIAL_MIN_RANGE
    range_max = INITIAL_MAX_RANGE
    lengh = int(input("Input Prefix Length: "))
    prefix = RMD160_HASH[:lengh]  # Use the first few characters of rmd160 as prefix

    while range_max - range_min > 1:
        # Run keyhunt for prefix search
        process = run_keyhunt(prefix, range_min, range_max)
        private_key = process_keyhunt_output(process, prefix)

        if private_key:
            # Save the found private key
            with open(FOUND_KEYS_FILE, "a") as f:
                f.write(f"{private_key}\n")

            # Verify the private key
            if verify_rmd160(private_key, RMD160_HASH):
                logging.info(f"Success! Found private key: {private_key}")
                break

            # Narrow the range and switch to sequential search
            range_min = int(private_key, 16)
            range_max = int(range_min + (range_max - range_min) * NARROW_FACTOR)
            logging.info(f"Narrowing search range: {range_min} - {range_max}")

            # Run sequential search from the matched private key
            process = run_keyhunt(prefix, range_min, range_max, mode="sequential", start_key=private_key)
            private_key = process_keyhunt_output(process, prefix)

            if private_key and verify_rmd160(private_key, RMD160_HASH):
                logging.info(f"Success! Found private key: {private_key}")
                break
        else:
            # Expand the range if no matches are found
            range_min += int((range_max - range_min) * NARROW_FACTOR)
            logging.info(f"No prefix match found. Expanding search range: {range_min} - {range_max}")

    logging.info("Search completed.")


if __name__ == "__main__":
    main()
