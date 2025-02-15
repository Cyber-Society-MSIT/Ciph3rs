import hashlib
import argparse
import os
from datetime import datetime

# Supported hash types
hash_names = [
    'blake2b', 
    'blake2s', 
    'md5', 
    'sha1', 
    'sha224', 
    'sha256', 
    'sha384', 
    'sha3_224', 
    'sha3_256', 
    'sha3_384', 
    'sha3_512', 
    'sha512',
]

def crack_hashes(hashes, wordlist, hash_type):
    """Crack hashes using a wordlist.
    Args:
        hashes (list): List of hashes to crack.
        wordlist (str): Path to the wordlist file.
        hash_type (str): Hash type (e.g., md5, sha256).
    """
    # Get the hash function
    hash_fn = getattr(hashlib, hash_type)
    cracked = {}
    
    # Open the wordlist and start cracking
    try:
        with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            print(f"[*] Starting cracking using {hash_type}...")
            for line in f:
                word = line.strip()
                if not word:
                    continue
                
                hashed_word = hash_fn(word.encode()).hexdigest()
                if hashed_word in hashes:
                    print(f"[+] Hash cracked! {hashed_word} : {word}")
                    cracked[hashed_word] = word
                    
                    # Remove cracked hash from the list
                    hashes.remove(hashed_word)
                    
                    # If all hashes are cracked, stop
                    if not hashes:
                        break
        if hashes:
            print(f"[!] Some hashes couldn't be cracked: {hashes}")
    except Exception as e:
        print(f"[!] Error: {e}")
    
    return cracked

def main():
    # Argument parser setup
    parser = argparse.ArgumentParser(
        description='Hash Cracker Tool',
        usage='python Hbrute.py -m <method> -H <hashfile> -w <wordlist>'
    )
    parser.add_argument('-M', '--method', help='Hash method (e.g., md5, sha256)', required=True)
    parser.add_argument('-H', '--hashfile', help='File containing hashes to crack', required=True)
    parser.add_argument('-W', '--wordlist', help='Wordlist file for cracking', required=True)
    
    # Show help if no arguments are provided
    import sys
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    args = parser.parse_args()
    
    # Validate hash method
    if args.method not in hash_names:
        print(f"[!] Invalid hash type: {args.method}, supported types are: {hash_names}")
        sys.exit(1)
    
    # Validate hash file
    if not os.path.isfile(args.hashfile):
        print(f"[!] Hash file not found: {args.hashfile}")
        sys.exit(1)
    
    # Validate wordlist file
    if not os.path.isfile(args.wordlist):
        print(f"[!] Wordlist file not found: {args.wordlist}")
        sys.exit(1)
    
    # Load hashes from file
    try:
        with open(args.hashfile, 'r') as f:
            hashes = {line.strip() for line in f if line.strip()}
    except Exception as e:
        print(f"[!] Error reading hash file: {e}")
        sys.exit(1)
    
    # Start cracking
    start_time = datetime.now()
    cracked = crack_hashes(hashes, args.wordlist, args.method)
    end_time = datetime.now()
    duration = end_time - start_time
    
    # Display results
    print("\n=== Cracking Results ===")
    if cracked:
        for h, pwd in cracked.items():
            print(f"[+] {h} : {pwd}")
    else:
        print("[!] No hashes were cracked.")
    print(f"[*] Completed in {duration}")

if __name__ == '__main__':
    main()
