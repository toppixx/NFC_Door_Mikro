//  Phase 1:
//    TDAT->init()->get_random_string(32)
//
//
//  Phase 2:
//    TDAT->check(tdat,passphrase,iv)->boolen
//        true
//            TDAT->update(tdat,passphrase,iv)
//        false
//            TDAT->init()
//
//
//  Phase 3:
//    TDAT->check(tdat,passphrase,iv)->boolen
//        true
//            TDAT->init()
//        false
//            TDAT->init()
//
//
// TDAT->check(newTdat, oldTdat,passphrase,iv)
// SHA256(oldTdat+passphrase+iv)=newTdat
//
//
// TDAT->update(tdat,passphrase,iv)->SHA256(oldTdat+passphrase+iv)
//
//
//
#ifndef TDATCHECKER_H
#define TDATCHECKER_H
#include <Arduino.h>

//#define ESP8266 TRUE

class TDATchecker {
    public:
        TDATchecker();
        ~TDATchecker();
        String init();
        String calcSignature(const char* signature, const uint8_t* iv, const uint8_t* encKey); //sigSTring should be TDAT, but could be also include further charecters
        bool check(String incomingSignature, const char* oldSignature, const uint8_t* iv, const uint8_t* encKey);



    private:

};
#endif
