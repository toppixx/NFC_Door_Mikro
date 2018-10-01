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
#include "TDATchecker.h"
#include "Crypto.h"

TDATchecker::TDATchecker(){}

TDATchecker::~TDATchecker(){}

String  TDATchecker::init()
{
  //not used in this context
  String rndString = "";
  for(unsigned char i=0; i++; i<32)
    rndString = rndString + char(random(1,254));
  return  rndString;
}

String TDATchecker::update(String oldTDAT, String passphrase, String iv)
{
  byte sha256Buffer[33];
  String strInBuf ="";
  strInBuf = oldTDAT+ passphrase + iv;
  char chrInBuf[strInBuf.length()];
  strInBuf.toCharArray(chrInBuf, strInBuf.length());

  SHA256 shaHashen = SHA256();
  shaHashen.doUpdate(chrInBuf);
  shaHashen.doFinal(sha256Buffer);

  char sha256HexBuffer[32*3]; //make a 32*2+32-1+1 buffer for 32*2 hex digits 32-1 ' ' +1 0 string exit
  for (unsigned int i = 0 ; i<32; i++)
      sprintf(&sha256HexBuffer[i*2], "%02X ",sha256Buffer[i]);
  sha256HexBuffer[32*3-1] = 0; //remove the last ' ' and replace it with string ending 0
  return String(sha256HexBuffer);
}
bool TDATchecker::check(String incTDAT, String oldTDAT, String passphrase, String iv)
{
  bool retval = false;
  byte sha256Buffer[33];
  String strInBuf ="";

  strInBuf = oldTDAT + passphrase + iv;
  char chrInBuf[strInBuf.length()];
  strInBuf.toCharArray(chrInBuf, strInBuf.length());

  SHA256 shaHashen = SHA256();
  shaHashen.doUpdate(chrInBuf);
  shaHashen.doFinal(sha256Buffer);

  char sha256HexBuffer[32*3]; //make a 32*2+32-1+1 buffer for 32*2 hex digits 32-1 ' ' +1 0 string exit
  for (unsigned int i = 0 ; i<32; i++)
      sprintf(&sha256HexBuffer[i*2], "%02X ",sha256Buffer[i]);
  sha256HexBuffer[32*3-1] = 0; //remove the last ' ' and replace it with string ending 0

  if(String(sha256HexBuffer) == incTDAT)
      retval = true;

  return retval;
}
