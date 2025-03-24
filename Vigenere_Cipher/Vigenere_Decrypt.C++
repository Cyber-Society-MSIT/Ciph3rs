// The Vigenere Cipher, a method of decrypting alphabetic text using a series of Caesar ciphers based on the letters of a keyword.

// Header Files and Namespace
#include <iostream>     // for input and output operations
#include <string>       // For handling string operations
using namespace std;    // avoid writing std:: before standard functions like cout, cin

// Key generate the function
string generateKey(const string& text, const string& key) {
    string newKey;                          // function extends the key to match the length of the plaintext               
    int keyLength = key.length();     
    for (size_t i = 0; i < text.length(); ++i) {
        if (isalpha(text[i])) {
            newKey += key[i % keyLength];
        } else {                            // If the plaintext contains non-alphabetic characters 
            newKey += text[i];             // (spaces, punctuation), they remain unchanged in the key
        }                                 // The key is repeated cyclically until it covers the whole text.
    }
    return newKey;
}

// Vigenere Encryption Function
string vigenereEncrypt(const string& text, const string& key) {
    string encryptedText;
    string newKey = generateKey(text, key);   // Calls generateKey() to get a key matching the text length
    
    for (size_t i = 0; i < text.length(); ++i) {
        if (isalpha(text[i])) {
            char shift = toupper(newKey[i]) - 'A';
            if (isupper(text[i])) {
                encryptedText += char((text[i] - 'A' + shift) % 26 + 'A'); // Encrypt upper case
            } else {
                encryptedText += char((text[i] - 'a' + shift) % 26 + 'a'); // Encrypt lower case
            }
        } else {
            encryptedText += text[i];   // If not an alphabetic character, it remains unchanged.
        }
    }
    return encryptedText;                                                                             
}

// Vigenere Decryption Function
string vigenereDecrypt(const string& text, const string& key) {
    string decryptedText;
    string newKey = generateKey(text, key);   // Calls generateKey() to get a key matching the text length
    
    for (size_t i = 0; i < text.length(); ++i) {
        if (isalpha(text[i])) {
            char shift = toupper(newKey[i]) - 'A';
            if (isupper(text[i])) {
                decryptedText += char((text[i] - 'A' - shift + 26) % 26 + 'A'); // Decrypt upper case
            } else {
                decryptedText += char((text[i] - 'a' - shift + 26) % 26 + 'a'); // Decrypt lower case
            }
        } else {
            decryptedText += text[i];   // If not an alphabetic character, it remains unchanged.
        }
    }
    return decryptedText;                                                                             
}

// The main function
int main() {
    string text, key;
    cout << "Enter the text: ";  // The user to enter the plaintext
    getline(cin, text);
    cout << "Enter the key: ";   // The user to enter the encryption key
    getline(cin, key);
    
    string encryptedText = vigenereEncrypt(text, key); // Calls the encryption process   
    cout << "Encrypted Text: " << encryptedText << endl; // Display encrypted message

    string decryptedText = vigenereDecrypt(encryptedText, key); // Calls the decryption process
    cout << "Decrypted Text: " << decryptedText << endl; // Display decrypted message
    
    return 0;                                                  
}
