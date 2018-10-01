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
        String update(String oldTDAT, String passphrase, String iv);
        bool check(String incTDAT, String oldTDAT, String passphrase, String iv);



    private:

};
#endif
