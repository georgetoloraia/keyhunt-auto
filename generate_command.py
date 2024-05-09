#!/usr/bin/env python3
import random

def create_and_run_command(minimal, maximum):
    command = f'./keyhunt -t 8 -m rmd160 -r {minimal}:{maximum} -f 66.rmd -l compress -q -R'
    print(command)

def generate_command():
    # Generate random values for minimal and maximum
    minimal = random.randint(36893488147419103232, 73786976294838206463)
    maximum = random.randint(36893488147419103232, 73786976294838206463)

    # Ensure minimal is less than maximum
    minimal, maximum = sorted([minimal, maximum])

    # Convert minimal and maximum to hexadecimal
    minimal_hex = hex(minimal)[2:]
    maximum_hex = hex(maximum)[2:]

    # Create and print the command
    create_and_run_command(minimal_hex, maximum_hex)

if __name__ == "__main__":
    generate_command()
