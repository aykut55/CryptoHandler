#include <iostream>
#include <cstring>
#include "src/CryptoHandler.h"

void EncryptDecryptHashBufferExample(CCryptoHandler& handler, ALG_ID encAlgId, ALG_ID hashAlgId, const std::vector<BYTE>& inputBuffer, const std::string& password)
{
    std::vector<BYTE> encryptedBuffer;
    std::vector<BYTE> decryptedBuffer;

    std::cout << "Encryption started. inputBuffer size: " << inputBuffer.size() << " bytes." << std::endl;
    std::cout << std::endl;

    if (handler.EncryptBuffer(encAlgId, inputBuffer, encryptedBuffer, password) < 0) {
        std::cerr << "Encryption failed: " << handler.GetLastErrorString() << std::endl;
        return;
    }

    std::cout << "Encryption succeeded. Encrypted size: " << encryptedBuffer.size() << " bytes." << std::endl;
    std::cout << std::endl;

    std::cout << "Decryption started. Buffer size: " << encryptedBuffer.size() << " bytes." << std::endl;
    std::cout << std::endl;

    if (handler.DecryptBuffer(encAlgId, encryptedBuffer, decryptedBuffer, password) < 0) {
        std::cerr << "Decryption failed: " << handler.GetLastErrorString() << std::endl;
        return;
    }

    std::cout << "Decryption succeeded. Decrypted size: " << decryptedBuffer.size() << " bytes." << std::endl;
    std::cout << std::endl;

    if (inputBuffer == decryptedBuffer) {
        std::cout << "Success: Decrypted buffer matches the original input." << std::endl;
        std::cout << std::endl;
    }
    else {
        std::cerr << "Error: Decrypted buffer does not match the original input." << std::endl;
        std::cout << std::endl;
    }

    std::string hashOutput;

    if (handler.HashBuffer(hashAlgId, inputBuffer, hashOutput) != 0) {
        std::cerr << "Hashing failed: " << handler.GetLastErrorString() << std::endl;
        return;
    }

    std::string inputText(inputBuffer.begin(), inputBuffer.end());
    std::cout << "Input       : " << inputText << std::endl;
    std::string outputText(decryptedBuffer.begin(), decryptedBuffer.end());
    std::cout << "Output      : " << inputText << std::endl;
    std::cout << "SHA-256 Hash: " << hashOutput << std::endl;
    std::cout << std::endl;
}

void HashBufferExample(CCryptoHandler& handler, ALG_ID algId, const std::vector<BYTE>& buffer)
{
    /*
    std::string hashOutput;

    if (handler.HashBuffer(algId, buffer, hashOutput) != 0) {
        std::cerr << "Hashing failed: " << handler.GetLastErrorString() << std::endl;
        return;
    }

    std::cout << "SHA-256 Hash: " << hashOutput << std::endl;
    */
}


void StringEncryptionDecryptionHashExample(CCryptoHandler& handler, ALG_ID encAlgId, ALG_ID hashAlgId, const std::string& inputText, const std::string& password)
{
    std::string encryptedText, decryptedText, hash;

    // Encrypt
    if (handler.EncryptString(encAlgId, password, inputText, encryptedText) != 0) {
        std::cerr << "String encryption failed: " << handler.GetLastErrorString() << std::endl;
        return;
    }

    std::cout << "Encrypted (Base64): " << encryptedText << std::endl;
    std::cout << std::endl;

    // Decrypt
    if (handler.DecryptString(encAlgId, password, encryptedText, decryptedText) != 0) {
        std::cerr << "String decryption failed: " << handler.GetLastErrorString() << std::endl;
        return;
    }

    std::cout << "Decrypted: " << decryptedText << std::endl;
    std::cout << std::endl;

    // Check if original matches decrypted
    if (inputText == decryptedText) {
        std::cout << "Decrypted text matches original!" << std::endl;
        std::cout << std::endl;
    }
    else {
        std::cerr << "Decrypted text does not match original!" << std::endl;
        std::cout << std::endl;
    }

    // Hash
    if (handler.HashString(hashAlgId, inputText, hash) != 0) {
        std::cerr << "String hashing failed: " << handler.GetLastErrorString() << std::endl;
        return;
    }

    std::cout << "Input       : " << inputText << std::endl;
    std::cout << "Output      : " << inputText << std::endl;
    std::cout << "SHA-256 Hash: " << hash << std::endl;
    std::cout << std::endl;
}

void FileEncryptionDecryptionHashExample(CCryptoHandler& handler, ALG_ID encAlgId, ALG_ID hashAlgId, const std::string& password,
    const std::string& inputFile, const std::string& encryptedFile, const std::string& decryptedFile)
{
    if (handler.EncryptFile(encAlgId, inputFile, encryptedFile, password) != 0) {
        std::cerr << "File encryption failed: " << handler.GetLastErrorString() << std::endl;
        return;
    }

    std::cout << "File encryption succeeded." << std::endl;

    if (handler.DecryptFile(encAlgId, encryptedFile, decryptedFile, password) != 0) {
        std::cerr << "File decryption failed: " << handler.GetLastErrorString() << std::endl;
        return;
    }

    std::cout << "File decryption succeeded." << std::endl;

    std::string originalHash, decryptedHash;

    if (handler.HashFile(hashAlgId, inputFile, originalHash) != 0) {
        std::cerr << "Original file hashing failed." << std::endl;
        return;
    }

    if (handler.HashFile(hashAlgId, decryptedFile, decryptedHash) != 0) {
        std::cerr << "Decrypted file hashing failed." << std::endl;
        return;
    }

    std::cout << "Original file SHA-256 : " << originalHash << std::endl;
    std::cout << "Decrypted file SHA-256: " << decryptedHash << std::endl;

    if (originalHash == decryptedHash) {
        std::cout << "Decrypted file matches original!" << std::endl;
    }
    else {
        std::cerr << "Decrypted file does not match original!" << std::endl;
    }
}

void FileEncryptionDecryptionHashAsenkronExample(CCryptoHandler& handler, ALG_ID encAlgId, ALG_ID hashAlgId, const std::string& password,
    const std::string& inputFile, const std::string& encryptedFile, const std::string& decryptedFile)
{

    handler.EncryptFileWithCallback(encAlgId, inputFile, encryptedFile, password,
        []() { 
            std::cout << "Encryption started!\n"; },

        [](size_t processed, size_t total) {
            std::cout << "Encrypted: " << processed << " / " << total << " bytes\r";
        },

        [](int result) {
            if (result == 0)
                std::cout << "\nEncryption completed successfully.\n";
            else
                std::cerr << "\nEncryption failed!\n";
        }
    );

    //std::this_thread::sleep_for(std::chrono::seconds(1000));

    handler.DecryptFileWithCallback(
        encAlgId, encryptedFile, decryptedFile, password,
        []()
        { std::cout << "Decryption started!\n"; },
        [](size_t processed, size_t total) {
            std::cout << "Decrypted: " << processed << " / " << total << " bytes\r";
        },
        [](int result) {
            if (result == 0)
                std::cout << "\Decryption completed successfully.\n";
            else
                std::cerr << "\Decryption failed!\n";
        }
    );

    std::string hashOutput;

    handler.HashFileWithCallback(
        hashAlgId, inputFile, hashOutput,
        []() { std::cout << "Hashing started!\n"; },
        [](size_t processed, size_t total) {
            std::cout << "Hashed: " << processed << " / " << total << " bytes\r";
        },
        [&](int result) {
            if (result == 0)
                std::cout << "\nHash completed successfully: " << hashOutput << "\n";
            else
                std::cerr << "\nHash failed!\n";
        }
    );

    std::this_thread::sleep_for(std::chrono::seconds(5)); // Örnek bekleme (gerçek uygulamada daha iyi bir yöntem tercih edin)

    std::string originalHash, decryptedHash;

    if (handler.HashFile(hashAlgId, inputFile, originalHash) != 0) {
        std::cerr << "Original file hashing failed." << std::endl;
        return;
    }

    if (handler.HashFile(hashAlgId, decryptedFile, decryptedHash) != 0) {
        std::cerr << "Decrypted file hashing failed." << std::endl;
        return;
    }

    std::cout << "Original file SHA-256 : " << originalHash << std::endl;
    std::cout << "Decrypted file SHA-256: " << decryptedHash << std::endl;

    if (originalHash == decryptedHash) {
        std::cout << "Decrypted file matches original!" << std::endl;
    }
    else {
        std::cerr << "Decrypted file does not match original!" << std::endl;
    }
}

int main()
{
    // Cryptographic API Prototypes and Definitions
	CCryptoHandler cryptoHandler;

    std::string password = "MySecretPassword";

    std::string inputFileName = "../input_text.txt";
    std::string encryptedFileName = "../encrypted.aes";
    std::string decryptedFileName = "../decrypted.txt";

    std::string inputString = "This is an input string";
    std::string encryptedString = "";
    std::string decryptedString = "";

    char inputBuffer[] = { "Due to technical issues, the email system is having troubles sending to some providers" };
    char encryptedBuffer[4096];
    char decryptedBuffer[4096];

    std::string hashFile = "";
    std::string hashString = "";
    std::string hashBuffer = "";

    std::string inputText = "";

    int result;

#if 0
    // --------------------------------------------------------------------
    {
        // File encryption example
        std::cout << "Encrypting file..." << std::endl;
        result = cryptoHandler.EncryptFile(CALG_AES_256, inputFileName, encryptedFileName, password);

        // Wait for operation to complete
        while (cryptoHandler.IsRunning()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        std::cout << std::endl;
    }

    // --------------------------------------------------------------------
    {
        // File decryption example
        std::cout << "Decrypting file..." << std::endl;
        result = cryptoHandler.DecryptFile(CALG_AES_256, encryptedFileName, decryptedFileName, password);

        // Wait for operation to complete
        while (cryptoHandler.IsRunning()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        std::cout << std::endl;
    }

    // --------------------------------------------------------------------
    {
        //TODO : Read inputFile and decryptedFile within a loop and compare bytes.
    }

    // --------------------------------------------------------------------
    {
        // File hashing example
        std::cout << "Hashing file..." << std::endl;
        result = cryptoHandler.HashFile(CALG_MD5, inputFileName, hashFile);

        // Wait for operation to complete
        while (cryptoHandler.IsRunning()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        std::cout << std::endl;
    }


    // --------------------------------------------------------------------
    {
        // String encryption example
        result = cryptoHandler.EncryptString(CALG_AES_256, password, inputString, encryptedString);
        result = cryptoHandler.DecryptString(CALG_AES_256, password, encryptedString, decryptedString);

        // String hashing example
        result = cryptoHandler.HashString(CALG_MD5, inputString, hashString);

        std::cout << "Original: "  << inputString << std::endl;
        std::cout << std::endl;
        std::cout << "Encrypted: " << cryptoHandler.Base64Encode(encryptedString) << std::endl;
        std::cout << std::endl;
        std::cout << "Decrypted: " << decryptedString << std::endl;
        std::cout << std::endl;
        std::cout << "Hash: "      << hashString << std::endl;
        std::cout << std::endl;

        std::cout << std::endl;
    }

    // --------------------------------------------------------------------
    {
        //TODO: compare inputString and decryptedString.
    }


    // --------------------------------------------------------------------
    {
        // Buffer encryption example
        std::cout << "Encrypting buffer..." << std::endl;
        result = cryptoHandler.EncryptBuffer(CALG_AES_256, inputBuffer, encryptedBuffer, password);

        // Wait for operation to complete
        while (cryptoHandler.IsRunning()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        std::cout << std::endl;
    }

    // --------------------------------------------------------------------
    {
        // Buffer decryption example
        std::cout << "Decrypting buffer..." << std::endl;
        result = cryptoHandler.DecryptBuffer(CALG_AES_256, encryptedBuffer, decryptedBuffer, password);

        // Wait for operation to complete
        while (cryptoHandler.IsRunning()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        std::cout << std::endl;
    }

    // --------------------------------------------------------------------
    {
        //TODO: compare inputBuffer and decryptedBuffer.
    }

    // --------------------------------------------------------------------
    {
        // Buffer hashing example
        std::cout << "Hashing buffer..." << std::endl;
        result = cryptoHandler.HashFile(CALG_MD5, inputBuffer, hashBuffer);

        // Wait for operation to complete
        while (cryptoHandler.IsRunning()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        std::cout << std::endl;
    }
#endif

    std::cout << std::endl;
    std::cout << "========================================================" << std::endl;
    std::cout << "EncryptDecryptHashBufferExample" << std::endl;
    std::cout << "========================================================" << std::endl;
    std::cout << std::endl;

    inputText = "Due to technical issues, the email system is having troubles sending to some providers";
    std::vector<BYTE> inputBuffer1(inputText.begin(), inputText.end());
    EncryptDecryptHashBufferExample(cryptoHandler, CALG_AES_256, CALG_SHA_256, inputBuffer1, password);

    std::cout << std::endl;
    std::cout << "========================================================" << std::endl;
    std::cout << "StringEncryptionDecryptionHashExample" << std::endl;
    std::cout << "========================================================" << std::endl;
    std::cout << std::endl;

    inputString = "This is an input string";
    StringEncryptionDecryptionHashExample(cryptoHandler, CALG_AES_256, CALG_SHA_256, inputString, password);
    std::cout << std::endl;

    std::cout << std::endl;
    std::cout << "========================================================" << std::endl;
    std::cout << "FileEncryptionDecryptionHashExample" << std::endl;
    std::cout << "========================================================" << std::endl;
    std::cout << std::endl;

    inputFileName = "../input_text.txt";
    FileEncryptionDecryptionHashExample(cryptoHandler, CALG_AES_256, CALG_SHA_256, password, inputFileName, encryptedFileName, decryptedFileName);
    std::cout << std::endl;

    std::cout << std::endl;
    std::cout << "========================================================" << std::endl;
    std::cout << "FileEncryptionDecryptionHashAsenkronExample" << std::endl;
    std::cout << "========================================================" << std::endl;
    std::cout << std::endl;

    inputFileName = "../input_binary.rar";
    inputFileName = "../input_text.txt";
    FileEncryptionDecryptionHashAsenkronExample(cryptoHandler, CALG_AES_256, CALG_SHA_256, password, inputFileName, encryptedFileName, decryptedFileName);
    std::cout << std::endl;
}
