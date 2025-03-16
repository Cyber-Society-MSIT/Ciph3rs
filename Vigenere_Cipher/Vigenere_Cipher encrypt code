//The Vigenere Cipher, a method of encrypting alphabetic text using a series of Caesar ciphers based on the letters of a keyword.

//Header Files and Namespace
#include <iostream>     // for input and output operations
#include <string>       //For handling string operations
using namespace std;    //avoid writing std:: before standard functions like cout, cin

//Key generate the function
string generateKey(const string& text, const string& key) {
    string newKey;                          //function extends the key to match the length of the plaintext               
    int keyLength = key.length();     
    for (size_t i = 0; i < text.length(); ++i) {
        if (isalpha(text[i])) {
            newKey += key[i % keyLength];
        } else {                            //If the plaintext contains non-alphabetic characters 
            newKey += text[i];             // (spaces, punctuation), they remain unchanged in the key
        }                                 // The key is repeated cyclically until it covers the whole text.
    }
    return newKey;
}

//Vigenere Encryption Function
string vigenereEncrypt(const string& text, const string& key) {
    string encryptedText;
    string newKey = generateKey(text, key);   //Calls generateKey() to get a key matching the text length
    
    for (size_t i = 0; i < text.length(); ++i) {
        if (isalpha(text[i])) {
            char shift = toupper(newKey[i]) - 'A';
            if (isupper(text[i])) {
                encryptedText += char((text[i] - 'A' + shift) % 26 + 'A');//Applies the formula of an upper case letters: 
                                                                         //EncryptedChar=(TextChar−'A' + shift) mod 26+'A'
            } else {
                encryptedText += char((text[i] - 'a' + shift) % 26 + 'a');//Applies the formula of lower case letters:
            }                                                            //EncryptedChar=(TextChar−'a' + shift) mod 26+'a'
        } else {
            encryptedText += text[i];   //if it is not an alphabetic character,it remains unchanged.
        }
    }
    return encryptedText;                                                                             
}                                                                                                     
                                                                                        
//The main function
int main() {
    string text, key;
    cout << "Enter the text: ";  //the user to enter the plaintext
    getline(cin, text);
    cout << "Enter the key: ";   //the user to enter the encryption key
    getline(cin, key);
                                                                                         
    string encryptedText = vigenereEncrypt(text, key); // calls the encryption process   
    cout << "Encrypted Text: " << encryptedText << endl; //encrypted the msg
    
    return 0;                       //Example Calculation:                           
}                                  // Plaintext: CRYPTOGRAPHY 
                                  //  Key: HIDING
                                 // Encryption Process (Step-by-Step): (this is the base64 Alphabet)
                                // 'C' (shift by 'H' = 7) → 'J'
                               //  'R' (shift by 'I' = 8) → 'Z'
                              //   'Y' (shift by 'D' = 3) → 'B'
                             //    'P' (shift by 'I' = 8) → 'X'      
                            //     'T' (shift by 'N' = 13)→ 'G'
                           //      'O' (shift by 'G' = 6) → 'U'
                          //       'G' (shift by 'H' = 7) → 'N'
                         //        'R' (shift by 'I' = 8) → 'Z'
                        //         'A' (shift by 'D' = 3) → 'D'
                       //          'P' (shift by 'I' = 8) → 'X'
                      //           'H' (shift by 'N' = 13)→ 'U' 
                     //            'Y' (shift by 'G' = 6) → 'E'
                    //               Ciphertext: JZBXGUNZDXUE
