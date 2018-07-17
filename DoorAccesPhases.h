#ifndef DOORACCESPHASES_H
#define DOORACCESPHASES_H
#include <Arduino.h>

//#define ESP8266 TRUE

class DoorAccesPhases {
    public:
        DoorAccesPhases();
        ~DoorAccesPhases();
        // bool Phase1(char* nfcUUID, unsigned char nfcUUIDLength, char* baseURL, String baseURLlength);
        // bool Phase2(void);
        // bool Phase3(void);
        // void reset(void);
        void init(char* udid); //evtl auf 32Byte prüfen
        bool Phase1(char* uuid, String baseURL);
        bool Phase2(void);
        bool Phase3(String& ndefPayBuff);
        void reset(void);
    private:
        bool sha256Calc(char* strInBuf, byte* ArrOutBuf,byte ArrOutLen);

        // bool getRndSha256(char* charArrOut, unsigned char charArrOutLength); //last value should be guees...32 XD
        // bool getRnd32hexDigString(char* charArrOut, unsigned char charArrOutLength); //last value should be guees...32 XD
        bool getRndSha256(byte* ArrOut, byte ArrOutLength); //last value should be guees...32 XD
        String byteToHexString(char* charArr, unsigned char charArrLen);
        //String getRndSha256(); //last value should be guees...32 XD
        String getRnd32hexDigString(); //last value should be guees...32 XD
        char convertCharToHex(char ch);
        bool convertStringToByteArr(const char* input, byte* byteArrOutBuff, byte byteArrOutLength);
        void printBlock(uint8_t* block, int length);

        // char nfcUUID[32];
        // char nfcUDID[32];
        // char nfcAESEncryptionKey[16];
        // char nfcAESIV[16];
        // char nfcDataLoad[32];
        // char AESIV[16];
        // char TDAT[32];
        #define UDIDLen 17
        uint8_t UDID[UDIDLen];
        #define nfcUUIDLen 33
        char nfcUUID[nfcUUIDLen];
        #define nfcAESEncryptionKeyLen 17
        uint8_t nfcAESEncryptionKey[nfcAESEncryptionKeyLen];
        #define nfcAESCipherLen 33
        uint8_t nfcAESCipher[nfcAESCipherLen];
        #define nfcAESIVLen 17
        uint8_t nfcAESIV[nfcAESIVLen];
        #define nfcDataLoadLen 33
        char nfcDataLoad[nfcDataLoadLen];
        String httpBaseURL;
        #define httpTDATLen 33
        uint8_t httpTDAT[httpTDATLen];
        #define httpAESIVLen 17
        uint8_t httpAESIV[httpAESIVLen];
        #define httpAESEncryptionKeyLen 17
        uint8_t httpAESEncryptionKey[httpAESEncryptionKeyLen];
};
#endif
