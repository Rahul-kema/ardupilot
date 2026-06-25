#!/usr/bin/env python3

import sys
import hashlib
import subprocess
import datetime
import os

def get_section_lma(elf_path, section_name):
    result = subprocess.run(
        ['arm-none-eabi-objdump', '-h', elf_path],
        capture_output=True, text=True
    )
    for line in result.stdout.split('\n'):
        parts = line.split()
        if len(parts) >= 5 and parts[1] == section_name:
            return int(parts[4], 16)
    raise ValueError(f"Section {section_name} not found")

def compute_boundary(elf_path):
    text_lma = get_section_lma(elf_path, '.text')
    data_lma = get_section_lma(elf_path, '.data')
    return data_lma - text_lma

def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 compute_checksums.py <elf> <bin>")
        sys.exit(1)

    elf_path = sys.argv[1]
    bin_path = sys.argv[2]

    boundary = compute_boundary(elf_path)

    print("Boundary:", boundary, "bytes")

    with open(bin_path, 'rb') as f:
        firmware = f.read()

    code_region = firmware[:boundary]
    data_region = firmware[boundary:]

    code_checksum = sha256_bytes(code_region)
    data_checksum = sha256_bytes(data_region)

    print("CODE checksum:", code_checksum)
    print("DATA checksum:", data_checksum)

    with open('code_checksum.txt', 'w') as f:
        f.write(code_checksum)

    with open('data_checksum.txt', 'w') as f:
        f.write(data_checksum)

    print("Files generated: code_checksum.txt, data_checksum.txt")

if __name__ == '__main__':
    main()
