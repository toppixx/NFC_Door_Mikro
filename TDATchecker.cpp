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
#include "DoorAccesPhases.h"
TDATchecker::TDATchecker(){}

TDATchecker::~TDATchecker(){}

String  TDATchecker::init()
{
  //not used in this context
  //also not tested
  String rndString = "";
  for(unsigned char i=0; i++; i<32)
    rndString = rndString + char(random(1,254));
  return  rndString;
}


//
// AES aesEncryptor(httpAESEncryptionKey, httpAESIV, AES::AES_MODE_128, AES::CIPHER_ENCRYPT);
// aesEncryptor.process((uint8_t*)nfcUTIDnotStored, (uint8_t*)keyHash, cypherLen);
//
String TDATchecker::calcSignature(const char* signature, const uint8_t* iv, const uint8_t* encKey) //sigSTring should be TDAT, but could be also include further charecters
{
  Serial.println("------------------------------------------------------------------------");
  Serial.println("calculate next signature SHA256(AES128(signature,iv,encKey))");
  if(strlen(signature)==64)
  {
    Serial.println("signature");
    Serial.println(signature);
    char byteBuffer[strlen(signature)*2+1];
    AES aesEncryptor(encKey, iv, AES::AES_MODE_128, AES::CIPHER_ENCRYPT);
    aesEncryptor.process((const uint8_t*)signature,(uint8_t*) byteBuffer, strlen(signature));
    byteBuffer[strlen(signature)]=0;

    //writing AES cipher to HexDitsCharakters. With this ascii bytes a visible sha256 could be calculated
    //char aes128Buffer[strlen(signature)*2+1];
    //aes128Buffer[strlen(signature)*2]=0;

    for (int i = strlen(signature)-1; i>=0; i--)
    {
        char buffer[3];
        sprintf(&buffer[0], "%02X",byteBuffer[i]);
        byteBuffer[i*2] = buffer[0];
        byteBuffer[i*2+1] = buffer[1];
    }
    byteBuffer[strlen(signature)*2]=0;
    Serial.println("AES128(signature)(hex)");
    Serial.println(byteBuffer);
    char sha256Buffer[33];
    SHA256 shaHashen = SHA256();
    shaHashen.doUpdate(byteBuffer);
    shaHashen.doFinal((uint8_t*)sha256Buffer);
    sha256Buffer[32]=0;

    for (int i = 32-1 ; i>=0; i--)
    {
      char buffer[3];
      sprintf(&buffer[0], "%02X",sha256Buffer[i]);
      byteBuffer[i*2] = buffer[0];
      byteBuffer[i*2+1] = buffer[1];
    }
    byteBuffer[64]=0;

    Serial.print("SHA256(AES128(signature)) or nextSignature(hex):\t");
    Serial.println(byteBuffer);

  return String(byteBuffer);
  }
  else
    return String("signature to short");
}

bool TDATchecker::check(String incomingSignature, const char* oldSignature, const uint8_t* iv, const uint8_t* encKey)
{
  bool retval = false;
  String newSignature = calcSignature(oldSignature, iv, encKey);
  if(newSignature == incomingSignature)
      retval = true;

  return retval;
}
