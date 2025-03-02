def xor_encrypt(ptext,key):
    ptlen = len(ptext)
    klen = len(key)
    
    
    
    if (ptlen == klen):
        
        
        
        ct = ''.join(format(ord(ptext[i]) ^ ord(key[i]), '02x') for i in range (klen))
        
        print(f"your ciphertext: {ct}")
    
    elif (ptlen != klen):
        repeated_key = (key * ((len(ptext) // len(key)) + 1))[:len(ptext)]

       
        ciphertext = ''.join(chr(ord(p) ^ ord(k)) for p, k in zip(ptext, repeated_key))
        c_hex = ''.join(format(ord(c), '02x') for c in ciphertext)
        
        print(f"your ciphertext: {c_hex}")
        
    else :
        exit()
        
    
          
            
                                        
                                        
ptext = str(input("Enter the plain text: "))

key = str(input("Enter the secret key: "))

xor_encrypt(ptext,key)
