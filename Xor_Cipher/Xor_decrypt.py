def xor_decrypt(ctext, key):
    klen = len(key)
    
    
    
    ciphertext = ''.join(chr(int(ctext[i:i+2], 16)) for i in range(0, len(ctext), 2))
    
    
    repeated_key = (key * ((len(ciphertext) // klen) + 1))[:len(ciphertext)]
    
    ptext = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(ciphertext, repeated_key))
    
    print(f"Your decrypted text: {ptext}")
    
    return ptext


ctext = input("Enter the ciphertext (hex format): ")
key = input("Enter the secret key: ")


xor_decrypt(ctext, key)


