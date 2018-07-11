#ifndef DOORACCESPHASES_H
#define DOORACCESPHASES_H
#include <Arduino.h>
class DoorAccesPhases {
    public:
        DoorAccesPhases();
        ~DoorAccesPhases();
        // bool Phase1(char* nfcUUID, unsigned char nfcUUIDLength, char* baseURL, String baseURLlength);
        // bool Phase2(void);
        // bool Phase3(void);
        // void reset(void);
        String Phase1(String nfcUUID, String baseURL);
        bool Phase2(void);
        bool Phase3(void);
        void reset(void);
    private:
        // bool getRndSha256(char* charArrOut, unsigned char charArrOutLength); //last value should be guees...32 XD
        // bool getRnd32hexDigString(char* charArrOut, unsigned char charArrOutLength); //last value should be guees...32 XD
        bool getRndSha256(char* charArrOut, unsigned char charArrOutLength); //last value should be guees...32 XD

        //String getRndSha256(); //last value should be guees...32 XD
        String getRnd32hexDigString(); //last value should be guees...32 XD
        // char nfcUUID[32];
        // char nfcUDID[32];
        // char nfcAESEncryptionKey[16];
        // char nfcAESIV[16];
        // char nfcDataLoad[32];
        // char AESIV[16];
        // char TDAT[32];
        String nfcUUID;
        String nfcUDID;
        char nfcAESEncryptionKey[16];
        char nfcAESIV[16];
        String nfcDataLoad;
        String AESIV;
        String TDAT;
};
#endif
