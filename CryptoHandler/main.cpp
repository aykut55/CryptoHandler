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

void FileEncryptionDecryptionHashCallbackExample(CCryptoHandler& handler, ALG_ID encAlgId, ALG_ID hashAlgId, const std::string& password,
    const std::string& inputFile, const std::string& encryptedFile, const std::string& decryptedFile)
{
    long long elapsedTimeMSec = 0;

    bool isRunning = false;

    handler.EncryptFileWithCallback(encAlgId, inputFile, encryptedFile, password,
        [&]() {
            std::cout << "Encryption started!\n"; 
        },
        [&](size_t processed, size_t total) {
            std::cout << "Encrypted: " << processed << " / " << total << " bytes";
            std::cout << ", Elapsed: " << std::to_string(elapsedTimeMSec) << " ms";
            std::cout << "\r";
        },
        [&](int result) {
            if (result == 0)
            {
                std::cout << "\nEncryption completed successfully.\n";
                std::cout << "Elapsed Time : " << std::to_string(elapsedTimeMSec) << " ms" << std::endl;
            }                
            else
                std::cerr << "\nEncryption failed!\n";
        },
        isRunning,
        elapsedTimeMSec
    );

    std::cout << std::endl;
    std::cout << std::endl;

    elapsedTimeMSec = 0;

    isRunning = false;

    handler.DecryptFileWithCallback(encAlgId, encryptedFile, decryptedFile, password,
        [&]()
        { 
            std::cout << "Decryption started!\n"; 
        },
        [&](size_t processed, size_t total) {
            std::cout << "Decrypted: " << processed << " / " << total << " bytes";
            std::cout << ", Elapsed: " << std::to_string(elapsedTimeMSec) << " ms";
            std::cout << "\r";
        },
        [&](int result) {
            if (result == 0)
            {
                std::cout << "\nDecryption completed successfully.\n";
                std::cout << "Elapsed Time : " << std::to_string(elapsedTimeMSec) << " ms" << std::endl;
            }
            else
                std::cerr << "\nDecryption failed!\n";
        },
        isRunning,
        elapsedTimeMSec
    );

    std::cout << std::endl;
    std::cout << std::endl;

    elapsedTimeMSec = 0;

    isRunning = false;

    std::string hashOutput;

    handler.HashFileWithCallback(hashAlgId, inputFile, hashOutput,
        [&]() { 
            std::cout << "Hashing started!\n"; 
        },
        [&](size_t processed, size_t total) {
            std::cout << "Hashed: " << processed << " / " << total << " bytes";
            std::cout << ", Elapsed: " << std::to_string(elapsedTimeMSec) << " ms";
            std::cout << "\r";
        },
        [&](int result) {
            if (result == 0)
            {
                std::cout << "\nHash completed successfully: " << hashOutput << "\n";
                std::cout << "Elapsed Time : " << std::to_string(elapsedTimeMSec) << " ms" << std::endl;
            }                
            else
                std::cerr << "\nHash failed!\n";
        },
        isRunning,
        elapsedTimeMSec
    );

    std::cout << std::endl;
    std::cout << std::endl;




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

    std::cout << std::endl;
    std::cout << std::endl;

    std::cout << std::endl;
    std::cout << std::endl;
}

void FileEncryptionDecryptionHashAsenkronExample(CCryptoHandler& handler, ALG_ID encAlgId, ALG_ID hashAlgId, const std::string& password,
    const std::string& inputFile, const std::string& encryptedFile, const std::string& decryptedFile)
{
    long long elapsedTimeMSec = 0;

    bool isRunning = false;

    handler.EncryptFileAsync(encAlgId, inputFile, encryptedFile, password,
        [&]() {
            std::cout << "Encryption started!\n"; 
        },
        [&](size_t processed, size_t total) {
            std::cout << "Encrypted: " << processed << " / " << total << " bytes";
            std::cout << ", Elapsed: " << std::to_string(elapsedTimeMSec) << " ms";
            std::cout << "\r";
        },
        [&](int result) {
            if (result == 0)
            {
                std::cout << "\nEncryption completed successfully.\n";
                std::cout << "Elapsed Time : " << std::to_string(elapsedTimeMSec) << " ms" << std::endl;
            }
            else
                std::cerr << "\nEncryption failed!\n";
        },
        isRunning,
        elapsedTimeMSec
    );

    // Wait for operation to complete
    while (isRunning) { //handler.IsRunning()
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::cout << std::endl;
    std::cout << std::endl;

    elapsedTimeMSec = 0;

    isRunning = false;

    handler.DecryptFileAsync(encAlgId, encryptedFile, decryptedFile, password,
        [&]()
        { 
            std::cout << "Decryption started!\n"; 
        },
        [&](size_t processed, size_t total) {
            std::cout << "Decrypted: " << processed << " / " << total << " bytes";
            std::cout << ", Elapsed: " << std::to_string(elapsedTimeMSec) << " ms";
            std::cout << "\r";
        },
        [&](int result) {
            if (result == 0)
            {
                std::cout << "\nDecryption completed successfully.\n";
                std::cout << "Elapsed Time : " << std::to_string(elapsedTimeMSec) << " ms" << std::endl;
            }
            else
                std::cerr << "\nDecryption failed!\n";
        },
        isRunning,
        elapsedTimeMSec
    );

    // Wait for operation to complete
    while (isRunning) { //handler.IsRunning()
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::cout << std::endl;
    std::cout << std::endl;

    elapsedTimeMSec = 0;

    isRunning = false;

    std::string hashOutput;

    handler.HashFileAsync(hashAlgId, inputFile, hashOutput,
        [&]() { 
            std::cout << "Hashing started!\n"; 
        },
        [&](size_t processed, size_t total) {    
            std::cout << "Hashed: " << processed << " / " << total << " bytes";
            std::cout << ", Elapsed: " << std::to_string(elapsedTimeMSec) << " ms";
            std::cout << "\r";
        },
        [&](int result) {
            if (result == 0)
            {
                std::cout << "\nHash completed successfully: " << hashOutput << "\n";
                std::cout << "Elapsed Time : " << std::to_string(elapsedTimeMSec) << " ms" << std::endl;
            }
            else
                std::cerr << "\nHash failed!\n";
        },
        isRunning,
        elapsedTimeMSec
    );

    // Wait for operation to complete
    while (isRunning) { //handler.IsRunning()
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::cout << std::endl;
    std::cout << std::endl;




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

    std::cout << std::endl;
    std::cout << std::endl;

    std::cout << std::endl;
    std::cout << std::endl;
}

int main_()
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
    char encryptedBuffer[4096] = {};
    char decryptedBuffer[4096] = {};

    std::string hashFile = "";
    std::string hashString = "";
    std::string hashBuffer = "";

    std::string inputText = "";

    int result = 0;

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
    std::cout << "FileEncryptionDecryptionHashCallbackExample" << std::endl;
    std::cout << "========================================================" << std::endl;
    std::cout << std::endl;

    inputFileName = "../input_text.txt";
    FileEncryptionDecryptionHashCallbackExample(cryptoHandler, CALG_AES_256, CALG_SHA_256, password, inputFileName, encryptedFileName, decryptedFileName);
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

    return 0;
}

void OnStart() {
    std::cout << "Process started...\n";
}

void OnProgress(size_t current, size_t total) {
    std::cout << "Progress: " << current << " / " << total << "\n";
}

void OnCompletion(int result) {
    //std::cout << "Completed with result: " << result << "\n";
    if (result == 0) {
        std::cout << "Completed with successfully.\n";
    }
    else {
        std::cout << "Process terminated with result code: " << result << "\n";
    }
}

void OnError(int errorCode) {
    std::cerr << "Error occurred! Code: " << errorCode << "\n";
}

std::vector<BYTE> GenerateBytes(size_t byteCount, int flag = 0, BYTE fillByte = 0xAA)
{
    std::vector<BYTE> inputData(byteCount);

    if (flag == 0) {
        // Sabit değerle doldur
        std::fill(inputData.begin(), inputData.end(), fillByte);
    }
    else {
        // Rastgele veri üret
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dist(0, 255);

        for (size_t i = 0; i < byteCount; ++i) {
            inputData[i] = static_cast<BYTE>(dist(gen));
        }
    }

    return inputData;
}
/*
// 4096 baytlık sabit değerli veri (0xCC ile doldur)
std::vector<BYTE> fixedData = GenerateBytes(4096, 0, 0xCC);

// 8192 baytlık rastgele veri
std::vector<BYTE> randomData = GenerateBytes(8192, 1);
*/

int main2()
{
    CCryptoHandler crypto;

    std::string password = "test123";
    ALG_ID cryptoAlgId = CALG_AES_256;
    ALG_ID hashAlgId = CALG_SHA_256;

    // -------------------------------------------------------------------------------------
    std::cout << std::endl;
    std::cout << "============================================================================" << std::endl;
    std::cout << std::endl;
    
    std::string inputString = "Hello, this is a test message to encrypt, decrypt and hash!";

    std::vector<BYTE> inputData(inputString.begin(), inputString.end());
    std::vector<BYTE> encryptedData;
    std::vector<BYTE> decryptedData;
    std::vector<BYTE> outputData;
    std::string outputString = "";

    std::vector<BYTE> hashData;
    std::string hashString = "";
    // -------------------------------------------------------------------------------------

    bool isStopRequested = false;
    bool isRunning = false;
    long long elapsedTime = 0;
    int errorCode = 0;

    // -------------------------------------------------------------------------------------
    std::cout << "[*] inputString: " << inputString << std::endl;

    // -------------------------------------------------------------------------------------
    std::cout << std::endl;
    std::cout << "[*] Hashing..." << std::endl;
    crypto.HashBufferWithCallback(hashAlgId, inputData, hashData, hashString, &isStopRequested, &isRunning, &elapsedTime, &errorCode,
        OnStart, OnProgress, OnCompletion, OnError);

    std::cout << std::endl;
    std::cout << "[*] Hash result (string): " << hashString << std::endl;
/*
    std::cout << "[*] Hash result (bytes) : ";
    for (BYTE b : hashData) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b) << " ";
    }
    std::cout << std::dec << std::endl; // sonra desimale dönmek için
*/
    // -------------------------------------------------------------------------------------
    std::cout << std::endl;
    std::cout << "[*] Encrypting..." << std::endl;
    crypto.EncryptBufferWithCallback(cryptoAlgId, password, inputData, encryptedData, &isStopRequested, &isRunning, &elapsedTime, &errorCode,
        OnStart, OnProgress, OnCompletion, OnError);

    std::cout << std::endl;
    std::cout << "[*] Decrypting..." << std::endl;
    crypto.DecryptBufferWithCallback(cryptoAlgId, password, encryptedData, decryptedData, &isStopRequested, &isRunning, &elapsedTime, &errorCode,
        OnStart, OnProgress, OnCompletion, OnError);

    outputData = decryptedData;
    outputString = std::string(outputData.begin(), outputData.end());

    std::cout << std::endl;
    std::cout << "    Karsilastirma ve dogrulama" << "\t(inputString == outputString) " << std::endl;
    std::cout << std::endl;

    // Karşılaştırma ve doğrulama
    if (inputString == outputString) {
        std::cout << "[+] Decryption successful. Original and decrypted texts match.\n";
    }
    else {
        std::cerr << "[-] Decryption failed! Original and decrypted texts do not match.\n";
        std::cerr << "Original : " << inputString << "\n";
        std::cerr << "Decrypted: " << outputString << "\n";
    }

    std::cout << std::endl;
    std::cout << "[*] Encrypted String [ inputString  ] : " << inputString << std::endl;
    std::cout << "[*] Decrypted String [ outputString ] : " << outputString << std::endl;


    std::vector<BYTE> hashData1;
    std::vector<BYTE> hashData2;
    std::string hashString1 = "";
    std::string hashString2 = "";
    std::cout << std::endl;
    crypto.HashBufferWithCallback(hashAlgId, inputData, hashData1, hashString1, &isStopRequested, &isRunning, &elapsedTime, &errorCode,
        OnStart, OnProgress, OnCompletion, OnError);

    std::cout << std::endl;
    crypto.HashBufferWithCallback(hashAlgId, outputData, hashData2, hashString2, &isStopRequested, &isRunning, &elapsedTime, &errorCode,
        OnStart, OnProgress, OnCompletion, OnError);

    std::cout << std::endl;
    std::cout << "    Karsilastirma ve dogrulama" << "\t(input hashString == output hashString) " << std::endl;
    std::cout << std::endl;

    // Karşılaştırma ve doğrulama
    if (hashString1 == hashString2) {
        std::cout << "[+] Decryption successful. Original and decrypted texts match.\n";
    }
    else {
        std::cerr << "[-] Decryption failed! Original and decrypted texts do not match.\n";
        std::cerr << "Original : " << hashString1 << "\n";
        std::cerr << "Decrypted: " << hashString2 << "\n";
    }

    std::cout << std::endl;
    std::cout << "[*] Hash String [ inputString  ] : " << hashString1 << std::endl;
    std::cout << "[*] Hash String [ outputString ] : " << hashString2 << std::endl;


    std::cout << std::endl;
    std::cout << "    Karsilastirma ve dogrulama" << "\t(byte-by-byte comparison, inputData - decryptedData) " << std::endl;
    std::cout << std::endl;

    // Karşılaştırma ve doğrulama
    bool allBytesMatch = true;
    size_t mismatchIndex = 0;
    size_t minSize = std::min(inputData.size(), decryptedData.size());

    for (size_t i = 0; i < minSize; ++i) {
        if (inputData[i] != decryptedData[i]) {
            allBytesMatch = false;
            mismatchIndex = i;
            break;
        }
    }

    if (allBytesMatch && inputData.size() == decryptedData.size()) {
        std::cout << "[+] inputData vs decryptedData byte-by-byte comparison passed: All bytes match.\n";
    }
    else {
        std::cerr << "[-] inputData vs decryptedData comparison failed!\n";
        if (!allBytesMatch) {
            std::cerr << "Mismatch at byte index " << mismatchIndex
                << " (input: 0x" << std::hex << static_cast<int>(inputData[mismatchIndex])
                << ", decrypted: 0x" << static_cast<int>(decryptedData[mismatchIndex]) << std::dec << ")\n";
        }
        else {
            std::cerr << "Length mismatch (input size: " << inputData.size()
                << ", decrypted size: " << decryptedData.size() << ")\n";
        }
    }


    std::cout << std::endl;
    std::cout << "============================================================================" << std::endl;
    std::cout << std::endl;

    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;

    std::cout << std::endl;
    std::cout << "============================================================================" << std::endl;
    std::cout << std::endl;


    // 8192 baytlık rastgele veri
    std::vector<BYTE> randomData = GenerateBytes(8192, 1);

    inputData = randomData;

    std::cout << std::endl;
    std::cout << "[*] Hashing..." << std::endl;
    crypto.HashBufferWithCallback(hashAlgId, inputData, hashData, hashString, &isStopRequested, &isRunning, &elapsedTime, &errorCode,
        OnStart, OnProgress, OnCompletion, OnError);

    std::cout << std::endl;
    std::cout << "[*] Hash result (string): " << hashString << std::endl;

    std::cout << std::endl;
    std::cout << "[*] Encrypting..." << std::endl;
    crypto.EncryptBufferWithCallback(cryptoAlgId, password, inputData, encryptedData, &isStopRequested, &isRunning, &elapsedTime, &errorCode,
        OnStart, OnProgress, OnCompletion, OnError);

    std::cout << std::endl;
    std::cout << "[*] Decrypting..." << std::endl;
    crypto.DecryptBufferWithCallback(cryptoAlgId, password, encryptedData, decryptedData, &isStopRequested, &isRunning, &elapsedTime, &errorCode,
        OnStart, OnProgress, OnCompletion, OnError);

    outputData = decryptedData;

    std::cout << std::endl;
    crypto.HashBufferWithCallback(hashAlgId, inputData, hashData1, hashString1, &isStopRequested, &isRunning, &elapsedTime, &errorCode,
        OnStart, OnProgress, OnCompletion, OnError);

    std::cout << std::endl;
    crypto.HashBufferWithCallback(hashAlgId, outputData, hashData2, hashString2, &isStopRequested, &isRunning, &elapsedTime, &errorCode,
        OnStart, OnProgress, OnCompletion, OnError);

    std::cout << std::endl;
    std::cout << "    Karsilastirma ve dogrulama" << "\t(input hashString == output hashString) " << std::endl;
    std::cout << std::endl;

    // Karşılaştırma ve doğrulama
    if (hashString1 == hashString2) {
        std::cout << "[+] Decryption successful. Original and decrypted texts match.\n";
    }
    else {
        std::cerr << "[-] Decryption failed! Original and decrypted texts do not match.\n";
        std::cerr << "Original : " << hashString1 << "\n";
        std::cerr << "Decrypted: " << hashString2 << "\n";
    }

    std::cout << std::endl;
    std::cout << "[*] Hash String [ inputString  ] : " << hashString1 << std::endl;
    std::cout << "[*] Hash String [ outputString ] : " << hashString2 << std::endl;
    std::cout << std::endl;
    std::cout << "    Karsilastirma ve dogrulama" << "\t(byte-by-byte comparison, inputData - decryptedData) " << std::endl;
    std::cout << std::endl;

    std::cout << std::endl;

    // Karşılaştırma ve doğrulama
    allBytesMatch = true;
    mismatchIndex = 0;
    minSize = std::min(inputData.size(), decryptedData.size());

    for (size_t i = 0; i < minSize; ++i) {
        if (inputData[i] != decryptedData[i]) {
            allBytesMatch = false;
            mismatchIndex = i;
            break;
        }
    }

    if (allBytesMatch && inputData.size() == decryptedData.size()) {
        std::cout << "[+] inputData vs decryptedData byte-by-byte comparison passed: All bytes match.\n";
    }
    else {
        std::cerr << "[-] inputData vs decryptedData comparison failed!\n";
        if (!allBytesMatch) {
            std::cerr << "Mismatch at byte index " << mismatchIndex
                << " (input: 0x" << std::hex << static_cast<int>(inputData[mismatchIndex])
                << ", decrypted: 0x" << static_cast<int>(decryptedData[mismatchIndex]) << std::dec << ")\n";
        }
        else {
            std::cerr << "Length mismatch (input size: " << inputData.size()
                << ", decrypted size: " << decryptedData.size() << ")\n";
        }
    }


    std::cout << std::endl;
    std::cout << "============================================================================" << std::endl;
    std::cout << std::endl;


    // -------------------------------------------------------------------------------------
    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;

    return 0;
}





int main()
{
    CCryptoHandler crypto;

    std::string password = "secret123";
    
    std::string inputFileName = "../input_text.txt";       // Şifrelenecek dosya
    std::string encryptedFileName = "../encrypted.aes";
    std::string decryptedFileName = "../decrypted.txt";

    std::string inputFileHashResult = "";
    std::string decryptedFileHashResult = "";

    ALG_ID algId = CALG_AES_256;
    ALG_ID hashAlg = CALG_SHA_256;

    bool isRunning = false;
    bool stopRequested = false;
    long long elapsedTime = 0;
    int errorCode = 0;

    std::cout << "[*] Starting encryption process...\n";

    int result = crypto.EncryptFileStreamedWithCallback(
        algId,
        inputFileName,
        encryptedFileName,
        password,
        &stopRequested,
        &isRunning,
        &elapsedTime,
        &errorCode,
        OnStart,
        OnProgress,
        OnCompletion,
        OnError
    );

    std::cout << "[*] Encryption result code: " << result << "\n";
    std::cout << "[*] Elapsed time: " << elapsedTime << " ms\n";

    isRunning = false;
    stopRequested = false;
    elapsedTime = 0;
    errorCode = 0;

    std::cout << "[*] Starting decryption process...\n";

    result = crypto.DecryptFileStreamedWithCallback(
        algId,
        encryptedFileName,
        decryptedFileName,
        password,
        &stopRequested,
        &isRunning,
        &elapsedTime,
        &errorCode,
        OnStart,
        OnProgress,
        OnCompletion,
        OnError
    );

    std::cout << "[*] Decryption result code: " << result << "\n";
    std::cout << "[*] Elapsed time: " << elapsedTime << " ms\n";


    std::cout << "[*] Calculating hash...\n";

    result = crypto.HashFileStreamedWithCallback(
        hashAlg,
        inputFileName,
        inputFileHashResult,
        &stopRequested,
        &isRunning,
        &elapsedTime,
        &errorCode,
        OnStart,
        OnProgress,
        OnCompletion,
        OnError
    );

    std::cout << "[*] Hash result code: " << result << "\n";
    std::cout << "[*] InputFile Hash  : " << inputFileHashResult << "\n";
    std::cout << "[*] Elapsed time    : " << elapsedTime << " ms\n";


    result = crypto.HashFileStreamedWithCallback(
        hashAlg,
        decryptedFileName,
        decryptedFileHashResult,
        &stopRequested,
        &isRunning,
        &elapsedTime,
        &errorCode,
        OnStart,
        OnProgress,
        OnCompletion,
        OnError
    );

    std::cout << "[*] Hash result code   : " << result << "\n";
    std::cout << "[*] DecryptedFile Hash : " << decryptedFileHashResult << "\n";
    std::cout << "[*] Elapsed time       : " << elapsedTime << " ms\n";

    std::cout << "\n";
    std::cout << "\n";
    std::cout << "\n";

    std::cout << "[*] InputFile Hash     : " << inputFileHashResult << "\n";
    std::cout << "[*] DecryptedFile Hash : " << decryptedFileHashResult << "\n";



    return 0;
}