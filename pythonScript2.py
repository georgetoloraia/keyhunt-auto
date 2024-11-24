import subprocess
import logging

# Configurations
KEYHUNT_PATH = "./keyhunt"
RMD160_HASH = "739437bb3dd6d1983e66629c5f08c70e52769371"
ADDRESS = "1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9"
INITIAL_MIN_RANGE = 73786976294838206464
INITIAL_MAX_RANGE = 147573952589676412927
NARROW_FACTOR = 0.1
FOUND_KEYS_FILE = "found_keys.txt"
THREADS = None  # Set globally, input is deferred to main()

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")


def run_keyhunt(prefix, range_min, range_max, mode="vanity"):
    """
    Executes the keyhunt tool with the specified parameters.
    """
    range_min_hex = f"{range_min:064x}"  # Convert to 64-char hex
    range_max_hex = f"{range_max:064x}"
    
    command = [
        KEYHUNT_PATH,
        "-m", mode,
        "-l", "compress",
        "-f", "tests/unsolvedpuzzles.rmd",
        "-r", f"{range_min_hex}:{range_max_hex}",
        "-v", prefix,
        "-t", str(THREADS),
        "-R"
    ]
    
    logging.info(f"Running keyhunt: {command}")
    return subprocess.Popen(command, stdout=subprocess.PIPE, text=True)


def process_keyhunt_output(process):
    """
    Reads and processes the output of the keyhunt process.
    """
    private_key = None
    rmd160 = None

    for line in iter(process.stdout.readline, ''):
        if "Vanity Private Key:" in line:
            private_key = line.split(":")[1].strip()
            logging.info(f"Vanity Private Key found: {private_key}")
        elif "rmd160" in line:
            rmd160 = line.split(" ")[-1].strip()
            logging.info(f"rmd160 found: {rmd160}")

        if private_key and rmd160:
            return private_key, rmd160

    return None, None


def main():
    global THREADS
    THREADS = int(input("Input THREADS: ")) if not THREADS else THREADS
    range_min = INITIAL_MIN_RANGE
    range_max = INITIAL_MAX_RANGE
    length = 4  # Starting prefix length
    prefix = ADDRESS[:length]

    while range_max - range_min > 1:
        process = run_keyhunt(prefix, range_min, range_max)
        private_key, rmd160 = process_keyhunt_output(process)

        if private_key and rmd160 and int(private_key, 16) <= 147573952589676412927:
            # Check if range needs resetting
            if range_max - range_min < 1000000:
                range_min = INITIAL_MIN_RANGE
                range_max = INITIAL_MAX_RANGE
                length += 1
                prefix = ADDRESS[:length]
                logging.info(f"\nRange reset. New prefix length: {length}, prefix: {prefix}\n")

            # Save the private key
            with open(FOUND_KEYS_FILE, "a") as f:
                f.write(f"{private_key} : {rmd160}\n")

            # Check for correct rmd160
            if rmd160 == RMD160_HASH:
                logging.info(f"\n--- Success! ---\nFound private key: {private_key}\n")
                break

            # Narrow the range
            range_min = int(private_key, 16) + 1
            range_max = range_min + int((range_max - range_min) * NARROW_FACTOR)
        else:
            # Expand range slightly
            range_min += int((range_max - range_min) * NARROW_FACTOR)

        logging.info(f"Updated range: {range_min} - {range_max}")

    logging.info("Search completed.")


if __name__ == "__main__":
    main()
