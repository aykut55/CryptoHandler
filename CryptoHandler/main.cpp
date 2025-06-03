#include <iostream>
#include <cstring>
#include "src/CryptoHandler.h"

void EncryptDecryptBufferExample(CCryptoHandler& handler, ALG_ID algId, const std::vector<BYTE>& inputBuffer, const std::string& password)
{
    std::vector<BYTE> encryptedBuffer;
    std::vector<BYTE> decryptedBuffer;

    std::cout << "Encryption started. inputBuffer size: " << inputBuffer.size() << " bytes." << std::endl;
    std::cout << std::endl;

    if (handler.EncryptBuffer(algId, inputBuffer, encryptedBuffer, password) < 0) {
        std::cerr << "Encryption failed: " << handler.GetLastErrorString() << std::endl;
        return;
    }

    std::cout << "Encryption succeeded. Encrypted size: " << encryptedBuffer.size() << " bytes." << std::endl;
    std::cout << std::endl;

    std::cout << "Decryption started. Buffer size: " << encryptedBuffer.size() << " bytes." << std::endl;
    std::cout << std::endl;

    if (handler.DecryptBuffer(algId, encryptedBuffer, decryptedBuffer, password) < 0) {
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

    std::string inputText(inputBuffer.begin(), inputBuffer.end());
    std::cout << "Input     : " << inputText << std::endl;
    std::string outputText(decryptedBuffer.begin(), decryptedBuffer.end());
    std::cout << "Output    : " << inputText << std::endl;
    std::cout << std::endl;
}

void HashBufferExample(CCryptoHandler& handler, ALG_ID algId, const std::vector<BYTE>& buffer)
{
    std::string hashOutput;

    if (handler.HashBuffer(algId, buffer, hashOutput) != 0) {
        std::cerr << "Hashing failed: " << handler.GetLastErrorString() << std::endl;
        return;
    }

    std::cout << "Hash (hex): " << hashOutput << std::endl;
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

    const std::string inputText = "Due to technical issues, the email system is having troubles sending to some providers";
    std::vector<BYTE> inputBuffer1(inputText.begin(), inputText.end());

    std::cout << std::endl;
    EncryptDecryptBufferExample(cryptoHandler, CALG_AES_256, inputBuffer1, password);
    HashBufferExample(cryptoHandler, CALG_SHA_256, inputBuffer1);
    std::cout << std::endl;

}