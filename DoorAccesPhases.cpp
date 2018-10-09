#include "DoorAccesPhases.h"
//#include "AES.h"
#include "Crypto.h"
#include "Utils.h"
#include <ESP8266HTTPClient.h>
#include "ArduinoJson.h"
#include "TDATchecker.h"
DoorAccesPhases::DoorAccesPhases()
{
  char freeEr16[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  char freeEr32[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

  memcpy(UDID, freeEr32, 33);
  memcpy(nfcUUID, freeEr32, 33);
  memcpy(nfcAESEncryptionKey, freeEr16, 17);
  memcpy(nfcAESIV, freeEr16, 17);
  memcpy(nfcDataLoad, freeEr32, 33);
  httpBaseURL = "";
  memcpy(httpTDAT, freeEr32, 33);
  memcpy(httpAESIV, freeEr16, 17);
  memcpy(httpAESEncryptionKey, freeEr16, 17);
}

DoorAccesPhases::~DoorAccesPhases(){}

void DoorAccesPhases::init(const char* udid, String baseURL, String permissionStr)
{
  char freeEr16[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  char freeEr32[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  char freeEr64[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

  //char keyHash[65] = "";
  //for (unsigned int i = 0 ; i<32; i++)
  //    sprintf(&keyHash[i*2], "%02X",UDID[i]);
  //Serial.println("UDID");
  //Serial.println();
  memcpy(nfcUUID, freeEr32, 33);
  memcpy(nfcAESEncryptionKey, freeEr16, 17);
  memcpy(nfcAESIV, freeEr16, 17);
  memcpy(nfcDataLoad, freeEr32, 33);
  memcpy(httpTDAT, freeEr64, 65);
  memcpy(httpAESIV, freeEr16, 17);
  memcpy(httpAESEncryptionKey, freeEr16, 17);
  memcpy(UDID, freeEr32, 33);

  if(strlen(udid)==16)
  {
    memcpy(UDID, udid, strlen(udid));
    memcpy(httpAESEncryptionKey, udid, AES_IV_LENGTH);
  }
  else
    Serial.println("udid wrong length");
  if(permissionStr.length()==32)

    permissionStr.toCharArray(doorPermission, permissionStr.length()+1);
  else
    Serial.println("permissionStr wrong length");

  httpBaseURL = baseURL;

}

bool DoorAccesPhases::Phase1(const char* uuid)
{
  Serial.println("=================================Starting Phase 1====================================");
  Serial.println("Call Server with UUID to get TDAT");
  Serial.println("This TDAT is unique for each Door Access Request");
  Serial.println("and will be further processed to be unique for every Phase and dependend on the last once\n");
  if(String(uuid).length()<=32)
    memcpy(nfcUUID, uuid, strlen(uuid));
  else
  {
    Serial.println("uuid to long");
    return false;
  }
  String path = "DoorAcContPhase1/";
  String hexDigStr =  getRnd32hexDigString();
  String headerType = "content-type";
  String boundary = "--------------------------" + hexDigStr;
  String headerStr = "multipart/form-data; boundary=" + boundary;
  //String body = "multipart/form-data; boundary=----"+hexDigStr+"\n\r------"+hexDigStr+"\r\nContent-Disposition: form-data; name=\"userKeys\"\r\n\r\n"+nfcUUID+"\r\n------"+hexDigStr+"--";
  String body  = "--"+boundary+"\r\n"+"Content-Disposition: form-data; name=\"userKeys\"\r\n\r\n"+nfcUUID+"\r\n"+"--"+boundary+"--\r\n";
  HTTPClient http;
  http.begin(httpBaseURL + path);
  http.addHeader(headerType, headerStr);
  int httpCode = http.POST(body);

  if (httpCode < 0)
  {
    Serial.println("request error - " + httpCode);
    Serial.println(http.errorToString(httpCode));
    return false;
  }
  else
  {
    String httpRespo = http.getString();

    if(httpRespo.length()<200)
    {
      StaticJsonBuffer<200> jsonBuffer;
      JsonObject& jsonObject = jsonBuffer.parseObject(httpRespo);

      if (!jsonObject.success())
      {
        Serial.println("parseObject() failed");
        return false;
      }
      else
      {
        trennlinie();
        Serial.println("print http respons");
        Serial.println(httpRespo);
        trennlinie();
        const char* tdatArr = jsonObject["returnToken"];
        const char* aesIV = jsonObject["iv"];
        bool sucConvAESIV = false;
        if (tdatArr)
        {
          if((String(tdatArr).length()) ==64)
          {
            memcpy(httpTDAT, tdatArr, strlen(tdatArr)+1);
            httpTDAT[strlen(tdatArr)]=0;
            Serial.print("\nrecieved and Stored returnToken as TDAT\nTDAT:\t");
            Serial.println((char*)httpTDAT);
          }
          else
          {
            Serial.println("TDAT wrong size");
            return false;
          }
        }
        else
        {
          Serial.println("no returnToken in JsonBuffer");
          return false;
        }

        if (aesIV)
        {
          byte ivBuffer[AES_IV_LENGTH+1];
          sucConvAESIV = convertStringToByteArr(aesIV, ivBuffer, AES_IV_LENGTH);
          if(sucConvAESIV)
          {
            Serial.println(aesIV);
            Serial.println((char*)ivBuffer);
            memcpy(httpAESIV, ivBuffer, AES_IV_LENGTH);
            httpAESIV[AES_IV_LENGTH]=0;

            Serial.print("\nrecieved and Stored iv\nhttpAESIV:\t");
            Serial.println((char*)httpAESIV);
            printBlock(ivBuffer, AES_IV_LENGTH);
          }
          else
          {
            Serial.println("converting iv failed");
            return false;
          }
        }
        else
        {
          Serial.println("no iv in JsonBuffer");
          return false;
        }
      }
    }
    else
    {
      Serial.println("jsonBuffer to small");
      return false;
    }

    return true;
  }
}
bool DoorAccesPhases::Phase2()
{
  Serial.println("\n=================================Starting Phase 2====================================");
  Serial.println("Starting Phase 2 Server Call with SHA256(TDAT+UDID)");
  Serial.println("going to Calculate SHA256(TDAT+UDID)");
  Serial.println("This Hash gives the Server information about the calling Door ID");
  Serial.println("and the used EncryptionKey to send Data that must be kept secret\n");
  String path = "DoorAcContPhase2/";
  unsigned char sha256length = 32;
  uint8_t sha256Buffer[65] ="";
  char keyHash[65] ="";
  keyHash[64] =0;

  do {//heap shonen
    uint8_t plainUDID_TDATlength = UDIDLen +httpTDATLen;
    char plainUDID_TDATbuffer[plainUDID_TDATlength+1];
    memcpy(&plainUDID_TDATbuffer[0], httpTDAT, httpTDATLen);
    memcpy(&plainUDID_TDATbuffer[httpTDATLen-1], UDID, UDIDLen);
    trennlinie();
    Serial.println("Local SHA256 Generation\n");

    Serial.print("TDAT:\t\t");
    Serial.println((char*)httpTDAT);
    Serial.print("UDID:\t\t");
    Serial.println((char*)UDID);
    Serial.print("TDAT+UDID:\t");
    Serial.println(plainUDID_TDATbuffer);

    sha256Calc(plainUDID_TDATbuffer, sha256Buffer, sha256length);

    for (unsigned int i = 0 ; i<32; i++)
        sprintf(&keyHash[i*2], "%02X",sha256Buffer[i]);

    Serial.print("SHA256 Hash (hex):\t");
    Serial.println(keyHash);
    trennlinie();
    trennlinie();
    Serial.println("calculating new TDAT (TDAT2)");
    TDATchecker tdatChecker = TDATchecker();
    String TDAT2 = tdatChecker.calcSignature(httpTDAT, httpAESIV, httpAESEncryptionKey);
    TDAT2.toCharArray(httpTDAT, httpTDATLen);
    trennlinie();
  } while(false);

  HTTPClient http;
  int httpCode;
  do { // heap shonen
    /* code */

    String headerType = "content-type";
    String hexDigStr =  getRnd32hexDigString();
    String boundary = "--------------------------" + hexDigStr;
    String headerStr = "multipart/form-data; boundary=" + boundary;
    String content1  = "--"+boundary+"\r\n"+"Content-Disposition: form-data; name=\"userKeys\"\r\n\r\n"+String(nfcUUID)+"\r\n";
    String content2  = "--"+boundary+"\r\n"+"Content-Disposition: form-data; name=\"keyHash\"\r\n\r\n"+String(keyHash)+"\r\n";
    String contetn3 = "--"+boundary+"\r\n"+"Content-Disposition: form-data; name=\"TDAT2\"\r\n\r\n"+String(httpTDAT)+"\r\n"+"--"+boundary+"--\r\n";
    String body = content1 +content2 +contetn3;

    trennlinie();
    Serial.println("send http request to the Server");
    Serial.println("using the userKeys, SHA256(TDAT+UDID) keyHash, and TDAT2");
    Serial.println("http Body:");
    Serial.println("************************** Start *************************\n");
    Serial.println(body);

    Serial.println("*************************** End **************************\n");
    trennlinie();

    http.begin(httpBaseURL + path);
    http.addHeader(headerType, headerStr);
    int httpCode = http.POST(body);
  } while(false);

  if (httpCode < 0)
  {
    Serial.println("request error - " + httpCode);
    Serial.println(http.errorToString(httpCode));
    return false;
  }
  else
  {
    String httpRespo = http.getString();
    if(httpRespo.length()<200)
    {
      trennlinie();
      Serial.println("http Return from HttpRequest\n");
      Serial.println(httpRespo);
      trennlinie();

      StaticJsonBuffer<200> jsonBuffer;
      JsonObject& jsonObject = jsonBuffer.parseObject(httpRespo);

      if (!jsonObject.success())
      {
        Serial.println("parseObject() failed");
        return false;
      }
      else
      {
        #define HMAC_KEY_LENGTH 16
        #define AES_KEY_LENGTH 16
        #define AES_IV_LENGTH 16
        const char* aesCypher = jsonObject["cypher"];
        bool succAEScypher = false;
        if (aesCypher)
        {
            uint8_t cpyheredTextLen = strlen(aesCypher);
            uint8_t cypheredText[cpyheredTextLen];
            uint8_t cypherLen = cpyheredTextLen/2;
            uint8_t cypher[cypherLen];
            succAEScypher = convertStringToByteArr(aesCypher, cypher, cypherLen);

            if(succAEScypher)
            {
              trennlinie();
              Serial.println("going to decrypt the encyphered NFC-AES-Key from the httpMessage\n");
              uint8_t * keyEncrypt = UDID;
              char decrypted[cypherLen];

              Serial.print("httpAESEncryptionKey:\t");
              Serial.print((char*)keyEncrypt);
              printBlock(keyEncrypt,16);
              Serial.print("httpAESIV:\t\t");
              Serial.print((char*)httpAESIV);
              printBlock(httpAESIV, 16);
              Serial.print("cypher:\t\t\t");
              printBlock(cypher, cypherLen);

              AES aesDecryptor(keyEncrypt, httpAESIV, AES::AES_MODE_128, AES::CIPHER_DECRYPT);
              aesDecryptor.process((uint8_t*)cypher, (uint8_t*)decrypted, cypherLen);
              decrypted[cypherLen] = 0;
              Serial.println("\ndecrypted NFC-AES-Key");
              Serial.print("plainText: ");
              Serial.println((char*)decrypted);
              trennlinie();

              memcpy(nfcAESEncryptionKey, decrypted, nfcAESEncryptionKeyLen-1);
            }
            else
            {
              Serial.println("converting cypher failed");
              return false;
            }
          }
          else
          {
            Serial.println("couldnt get cypher");
            return false;
          }
          // decrypt
        }
      }
      else
      {
        Serial.println("jsonBuffer to small");
        return false;
      }
    }
    return true;
}


bool DoorAccesPhases::Phase3(String& ndefPayBuff)
{
  bool retval = false;
  Serial.println("\n=================================Starting Phase 3====================================");
  Serial.println("with the recieved NFC-AES-Key we are going to decrypt the UTID stored as Data on the NFC-Tag");
  Serial.println("after That the UTID will be send to the server");
  Serial.println("and the Server will resend a Permission=True Hash if the UTID fits to the UUID and has permission to the UDID");
  Serial.println("on the Local side we will calculate the same Hash and check against each other");
  Serial.println("The Permission=True Hash depends on the TDAT of the Access Request and a permissionTrue value thats unique to every door");
  Serial.println("This Hash is calculated as SHA256(AES128(TDAT+PermissionString, httpAESEncryptionKey))\n");
  trennlinie();
  Serial.println("extracting Data of the NFC-Tag\n");
  bool sucConvAESIV  = false;
  bool succAEScypher  = false;
  uint8_t cypherLen = 0;

  if((ndefPayBuff.length())<150)
  {
    StaticJsonBuffer<150> jsonBuffer;
    JsonObject& jsonObject = jsonBuffer.parseObject(ndefPayBuff);
    for(uint16_t i = 0;i<(ndefPayBuff.length());i++)
    {
      if(ndefPayBuff[i]=='.')
        ndefPayBuff[i] = ' ';
    }
    if (!jsonObject.success())
    {
      Serial.println("parseObject() failed");
      return false;
    }
    else
    {
      //#TODO give some nice Names
      const char* nfcAesCypherJson = jsonObject["cipher"];
      const char* nfcAesIvJson = jsonObject["iv"];


        if (nfcAesIvJson)
        {
          byte ivBuffer[AES_IV_LENGTH+1];
          sucConvAESIV = convertStringToByteArr(nfcAesIvJson, ivBuffer, AES_IV_LENGTH);
          if(sucConvAESIV)
          {
            memcpy(nfcAESIV, ivBuffer, AES_IV_LENGTH);

            Serial.print("AES-IV of NFC-Tag-Data:\t\t");
            Serial.print((char*)nfcAESIV);
            Serial.print(" ");
            printBlock(nfcAESIV, AES_IV_LENGTH);

          }
          else
            Serial.println("Byte String conversion of iv Entry failed ");
        }
        else
        {
          Serial.println("couldnt find iv Entry in Json");
        }
      if (nfcAesCypherJson)
      {
          uint8_t cpyheredTextLen = strlen((char*)nfcAesCypherJson);
          uint8_t cypheredText[cpyheredTextLen];
          cypherLen = cpyheredTextLen/2;
          uint8_t cypherBuffer[cypherLen];

          succAEScypher = convertStringToByteArr(nfcAesCypherJson, cypherBuffer, cypherLen);
          if(succAEScypher)
          {
            memcpy(nfcAESCipher, cypherBuffer, cypherLen);

            Serial.print("AesCypherText of NFC-Tag-Data:\t");
            printBlock(nfcAESCipher, cypherLen);
          }
        }
        else
        {
            Serial.println("couldnt find cipher Entry in Json");
        }
      }
    }
    else
      Serial.println("JsonBuffer to small");

    if( succAEScypher&&sucConvAESIV)
    {

      HTTPClient http;
      int httpCode;
      do{
        String body;
        String headerType;
        String headerStr;
        String path;
        do {  //make http request and delete all the strings no need after http
          /* code */      trennlinie();
        trennlinie();
        Serial.println("Starting to decrypt the NFC-Tag-Data\n");
        char decrypted[cypherLen+1];

        Serial.print("NFC-AES-Key:\t");
        Serial.print((char*)nfcAESEncryptionKey);
        printBlock(nfcAESEncryptionKey,16);
        Serial.print("nfcAESIV:\t");
        Serial.print((char*)nfcAESIV);
        printBlock((uint8_t*)nfcAESIV, 16);
        Serial.print("cypher:\t\t");
        printBlock((uint8_t*)nfcAESCipher,32);

        AES aesDecryptor(nfcAESEncryptionKey, nfcAESIV, AES::AES_MODE_128, AES::CIPHER_DECRYPT);
        aesDecryptor.process((uint8_t*)nfcAESCipher, (uint8_t*)decrypted, cypherLen);
        decrypted[cypherLen] = 0;

        char nfcUTIDnotStored[cypherLen+1];
        memcpy(nfcUTIDnotStored, decrypted, cypherLen);
        nfcUTIDnotStored[cypherLen]=0;

        Serial.print("plainText:\t");
        Serial.println(decrypted);
        Serial.println("\n\ndecrypted UTID of the NFC-Data with NFC-AES-Key recieved from Server\n");
        Serial.print("UTID:\t\t");
        Serial.println((char*)nfcUTIDnotStored);
        trennlinie();

        trennlinie();
        Serial.println("encrypt UTID with httpAESEncryptionKey to forward UTID to the Server\n");
        char* userKeys = &nfcUUID[0];
        char keyHash[cypherLen+1];
        unsigned char aes128BufferLen = cypherLen*2+1+cypherLen-1;  //(cypherLen*2)from 32 to 64 bit (+1) for 1 Null byte + (cypherLen-1) for 31 ' ' between two hex digits

        TDATchecker tdatChecker = TDATchecker();
        String TDAT3 = tdatChecker.calcSignature(httpTDAT, httpAESIV, httpAESEncryptionKey);
        TDAT3.toCharArray(httpTDAT, httpTDATLen);

        Serial.print("httpAESEncryptionKey:\t");
        Serial.print((char*)httpAESEncryptionKey);
        printBlock((uint8_t*)httpAESEncryptionKey,16);
        Serial.print("httpAESIV:\t\t");
        Serial.print((char*)httpAESIV);
        printBlock((uint8_t*)httpAESIV,16);
        Serial.print("plainText UTID:\t\t");
        Serial.print((char*)nfcUTIDnotStored);
        printBlock((uint8_t*)nfcUTIDnotStored,32);

        AES aesEncryptor(httpAESEncryptionKey, httpAESIV, AES::AES_MODE_128, AES::CIPHER_ENCRYPT);
        aesEncryptor.process((uint8_t*)nfcUTIDnotStored, (uint8_t*)keyHash, cypherLen);

        char aes128Buffer[aes128BufferLen]; //(cypherLen*2)from 32 to 64 bit (+1) for 1 Null byte + (cypherLen-1) for 31 ' ' between two hex digits
        for (unsigned int i = 0 ; i<cypherLen; i++)
            sprintf(&aes128Buffer[i*2], "%02X",keyHash[i]);
        aes128Buffer[aes128BufferLen-1] = 0; //get 0 string ending. overwriting last ' '



        Serial.println("encrypted UTID ready to be sent to the Server\n");
        Serial.print("cipherText:\t\t");
        Serial.println(aes128Buffer);
        trennlinie();

        trennlinie();
        Serial.println("variables send as http Request to the Server\n");
        Serial.print("UserKey:\t\t");
        Serial.println(userKeys);
        Serial.print("KeyHash:\t\t");
        Serial.println(aes128Buffer);
        Serial.print("TDAT3:\t\t\t");
        Serial.println(httpTDAT);
        trennlinie();
        Serial.println("00");

        path = "DoorAcContPhase3/";
        headerType = "content-type";
        String hexDigStr =  getRnd32hexDigString();
        String boundary  = "--------------------------" + hexDigStr;
        headerStr = "multipart/form-data; boundary=" + boundary;
        String content1  = "--"+boundary+"\r\n"+"Content-Disposition: form-data; name=\"userKeys\"\r\n\r\n"+String(userKeys)+"\r\n";
        String content2  = "--"+boundary+"\r\n"+"Content-Disposition: form-data; name=\"keyHash\"\r\n\r\n"+String(aes128Buffer)+"\r\n";
        String contetn3  = "--"+boundary+"\r\n"+"Content-Disposition: form-data; name=\"TDAT3\"\r\n\r\n"+String(httpTDAT)+"\r\n"+"--"+boundary+"--\r\n";
        body = content1 +content2 +contetn3;
        Serial.println(httpBaseURL);
        Serial.println(path);
        http.begin(httpBaseURL + path);
        http.addHeader(headerType, headerStr);
        Serial.print(body);
        httpCode = http.POST(body);
       } while(false); //to delete all the Strings no need anymore
     } while(false); //to delete all the Strings no need anymore


      if (httpCode < 0)
      {
        Serial.println("request error - " + httpCode);
        Serial.println(http.errorToString(httpCode));
        retval = false;
      }
      else
      {
        String httpRespo = http.getString();
        Serial.println("httpRespons:\t");
        Serial.println(httpRespo);
        if(httpRespo.length()<180)
        {
          StaticJsonBuffer<180> jsonBuffer;
          JsonObject& jsonObject = jsonBuffer.parseObject(httpRespo);
          //Serial.println("Jsoned");
          Serial.println("5");

          if (!jsonObject.success())
          {
            Serial.println("parseObject() failed");
            return false;
          }
          else
          {
            const char* doorAccesTokenFromServer = jsonObject["accessToken"];

            if (doorAccesTokenFromServer)
            {
              if((String(doorAccesTokenFromServer).length()) ==64)
              {
                trennlinie();

                Serial.println("got doorAccesToken as Server response from the Server\n");
                Serial.print("Server Token:\t\t");
                Serial.println(doorAccesTokenFromServer);
                trennlinie();

                trennlinie();
                Serial.println("calculate local Permission True Token SHA256(AES128(TDAT+doorPermissionString))\nand compare with the recieved one\n");
                //unsigned char sha256length = 32;
                uint8_t plainUDID_TDATlength = UDIDLen +httpTDATLen;
                char toHashChar[httpTDATLen+doorPermissionLen];
                memcpy(&toHashChar[0], httpTDAT, httpTDATLen);
                memcpy(&toHashChar[httpTDATLen-1], doorPermission, doorPermissionLen);

                Serial.print("TDAT:\t\t\t\t");
                Serial.println(String(httpTDAT));
                Serial.print("doorPermissionString:\t\t");//toHashStr = (self.TDAT+door.permissionStr)
                Serial.println(String(doorPermission));//toHashStr = (self.TDAT+door.permissionStr)
                Serial.print("TDAT+doorPermissionString:\t");//toHashStr = (self.TDAT+door.permissionStr)
                Serial.println(String(toHashChar));//toHashStr = (self.TDAT+door.permissionStr)

                Serial.println("\n\ncalculate AES128(TDAT+doorPermissionString)\n");

                Serial.print("plainText:\t\t\t");
                Serial.println(toHashChar);
                Serial.print("AESIV:\t\t\t\t");
                Serial.println((char*)httpAESIV);
                Serial.print("AESEncryptionKey:\t\t");
                Serial.println((char*)httpAESEncryptionKey);

                char encToken[strlen(toHashChar)];
                AES aesEncryptor(httpAESEncryptionKey, httpAESIV, AES::AES_MODE_128, AES::CIPHER_ENCRYPT);
                aesEncryptor.process((uint8_t*)toHashChar, (uint8_t*)encToken, strlen(toHashChar));

                char aes128Buffer[strlen(toHashChar)*2+1];
                for (unsigned int i = 0 ; i<strlen(toHashChar); i++)
                    sprintf(&aes128Buffer[i*2], "%02X",encToken[i]);

                Serial.println("\nAES cipher Result:\t");
                printBlock((uint8_t*)aes128Buffer,strlen(aes128Buffer)-1);
                trennlinie();
                trennlinie();

                Serial.println("SHA256 calculation of AES cipherText\n");
                byte sha256Hash[33];
                sha256Calc(aes128Buffer,sha256Hash,strlen(aes128Buffer) );

                char sha256Buffer[65];
                for (unsigned int i = 0 ; i<32; i++)
                    sprintf(&sha256Buffer[i*2], "%02X",sha256Hash[i]);

                sha256Buffer[65-1] = 0;
                Serial.print("SHA256 Hash (hex):\t");
                Serial.println(sha256Buffer);
                trennlinie();
                trennlinie();
                Serial.println("comparing Local and Token from Server\n");
                String doorAccesTokenLocalString = String(sha256Buffer);
                String doorAccesTokenFromServerString = String(doorAccesTokenFromServer);

                Serial.print("Local Token:\t\t");
                Serial.println(doorAccesTokenLocalString);
                Serial.print("Server Token:\t\t");
                Serial.println(doorAccesTokenFromServerString);

                if(doorAccesTokenFromServerString == doorAccesTokenLocalString)
                {
                  Serial.println("\n== == == Local and Server Token matched == == ==");
                  Serial.println("              =======================");
                  Serial.println("      ========     Open the Door     =======");
                  Serial.println("              =======================\n");

                  retval = true;
                }
              }
              else
                Serial.println("doorAccesToken wrong size");
              }
            else
            Serial.println("couldnt get doorAccesToken");
          }
          }
          else
          {
          Serial.println("jsonBuffer to small");
        }

    }
  }

  if(retval!=true)
  {
    Serial.println("\n!= != != Local and Server Token didn't match != != !=");
    Serial.println("                !=!=!=!=!=!=!=!=!=!=!=!=!");
    Serial.println("        !=!=!=!=!     Keep Door Shut    !=!=!=!=!");
    Serial.println("                !=!=!=!=!=!=!=!=!=!=!=!=!\n");

  }
  Serial.println("====================================Phase 3 finished=====================================\n\n");

  return retval;
}

void DoorAccesPhases::reset()
{
  char freeEr16[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  char freeEr32[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  char freeEr64[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

  memcpy(UDID, freeEr32, 33);
  memcpy(nfcUUID, freeEr32, 33);
  memcpy(nfcAESEncryptionKey, freeEr16, 17);
  memcpy(nfcAESIV, freeEr16, 17);
  memcpy(nfcDataLoad, freeEr32, 33);
  httpBaseURL = "";
  memcpy(httpTDAT, freeEr64, 65);
  memcpy(httpAESIV, freeEr16, 17);
  memcpy(httpAESEncryptionKey, freeEr16, 17);
}

void DoorAccesPhases::trennlinie()
{
  Serial.println("-----------------------------------------------------------");
}
bool DoorAccesPhases::sha256Calc(char* strInBuf, byte* byteOutBuf, byte byteOutLen)
{
  if(byteOutLen>=32)
  {
    SHA256 shaHashen = SHA256();
    shaHashen.doUpdate(strInBuf);
    shaHashen.doFinal(byteOutBuf);
    return true;
  }
  else
  Serial.println("byteOutLen should be >32");
  return false;
}

bool DoorAccesPhases::getRndSha256(byte* ArrOut, byte ArrOutLength) //last value should be guees...32 XD
{
  //Create a long rare value
  if (ArrOutLength<=32)
  {
    if(ArrOutLength !=32){Serial.println("Are you shure you want to recieve a hash with a shorter length then 32 Bytes /256 bits? well if you do its up to you. but if you dont know what you are doing take 32 bytes");}

    int timeDisturbedStrlength = 160;
    char timeDisturbedStr[timeDisturbedStrlength+1];
    timeDisturbedStr[timeDisturbedStrlength]=0;
    long long unsigned int u64_StartTick = Utils::GetMillis64(); //64 bit
    long long unsigned int u64_DisturbedTick = (u64_StartTick*3203431780337)%572199783953491*3203431780337;
    sprintf(timeDisturbedStr,"5l135hjlkal%lldkta52ljkjs0925ja1%lld", u64_StartTick, u64_DisturbedTick);

    sha256Calc(timeDisturbedStr, ArrOut, ArrOutLength);
    return true;
  }
  Serial.println("byteArrOutLength should be >?32");

  return false;
}
//bool DoorAccesPhases::getRnd32hexDigString(char* charArrOut, unsigned char charArrOutLength) //last value should be guees...32 XD
String DoorAccesPhases::getRnd32hexDigString()
{
  byte hexDig32length = 32;
  byte hexDig32Buffer[hexDig32length+1];
  hexDig32Buffer[hexDig32length] =0;

  getRndSha256(hexDig32Buffer, hexDig32length);
  unsigned char buffer = 0;
  //Serial.println(hexDig32Buffer);

  //if (charArrOutLength<=32)
  //{
  char bufferStr[2]="";
  bufferStr[1] = 0;
  String strOut="";
    for (unsigned char i=0; i<32; i++)
    {
      buffer = ((unsigned char)hexDig32Buffer[i])&0xF;
      if (buffer <10)
        buffer += 48;
      else
        buffer+=97-10;
      //charArrOut[i*2]  = buffer;

      sprintf(bufferStr, "%c",buffer);
      strOut += String(bufferStr);
      //Serial.println(strOut);

    }
  //  Serial.println(strOut);
    return strOut;

}

String makeRequest(String path, String headerType, String header, String body)
{


  //
  // //http.begin(BASE_URL + path);
  //
  // //http.addParameter("multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW", "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"nfc_tag\"\r\n\r\nA9:CD:85:89\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--");
  // http.addHeader(headerType, header);
  // Serial.println(http.getString());
  //
  // int httpCode = http.POST(body);
  //
  // if (httpCode < 0) {
  //   Serial.println("request error - " + httpCode);
  //   Serial.println(http.errorToString(httpCode));
  //
  //   return http.errorToString(httpCode);
  //
  // }
  // Serial.println(http.getString());
  //
  // if (httpCode != HTTP_CODE_OK) {
  //   return http.errorToString(httpCode);
  // }
  return "";
}

String DoorAccesPhases::byteToHexString(char* charArr, unsigned char charArrLen)
{
  char chrBuff[3];
  String strBuff="";
  for(unsigned int i = 0 ; i<charArrLen; i++)
  {
     sprintf(chrBuff, "%02X", charArr[i]);
     strBuff += String(chrBuff);
  }
  return strBuff;
}

bool DoorAccesPhases::convertStringToByteArr(const char* input, byte* byteArrOutBuff, byte byteArrOutLength)
{

  if( byteArrOutLength>=strlen(input)/2)
  {
    for(byte i = 0;i< strlen(input); i=i+4)
    {
      byteArrOutBuff[i/2] = convertCharToHex(input[i])*16;
      byteArrOutBuff[i/2] += convertCharToHex(input[i+1]);
      byteArrOutBuff[i/2+1] = convertCharToHex(input[i+2])*16;
      byteArrOutBuff[i/2+1] += convertCharToHex(input[i+3]);
    }
    return true;
  }
  else
    Serial.println("OutPut buffer to small");

  return false;
}

char DoorAccesPhases::convertCharToHex(char ch)
{
  char returnType;
  switch(ch)
  {
    case '0':
    returnType = 0;
    break;
    case  '1' :
    returnType = 1;
    break;
    case  '2':
    returnType = 2;
    break;
    case  '3':
    returnType = 3;
    break;
    case  '4' :
    returnType = 4;
    break;
    case  '5':
    returnType = 5;
    break;
    case  '6':
    returnType = 6;
    break;
    case  '7':
    returnType = 7;
    break;
    case  '8':
    returnType = 8;
    break;
    case  '9':
    returnType = 9;
    break;
    case  'A':
    returnType = 10;
    break;
    case  'a':
    returnType = 10;
    break;
    case  'B':
    returnType = 11;
    break;
    case  'b':
    returnType = 11;
    break;
    case  'C':
    returnType = 12;
    break;
    case  'c':
    returnType = 12;
    break;
    case  'D':
    returnType = 13;
    break;
    case  'd':
    returnType = 13;
    break;
    case  'E':
    returnType = 14;
    break;
    case  'e':
    returnType = 14;
    break;
    case  'F' :
    returnType = 15;
    break;
    case  'f':
    returnType = 15;
    break;
    default:
    returnType = 0;
    break;
 }
 return returnType;
}

// prints given block of given length in HEX
void DoorAccesPhases::printBlock(uint8_t* block, int length) {
  Serial.print(" { ");
  for (int i=0; i<length; i++) {
    Serial.print(block[i], HEX);
    Serial.print(" ");
  }
  Serial.println("}");
}
// bool door_acces_controll_phase_1(String UUID)
// {
//   String path = "/NFCDoorAcContPhase1/";
//
//   String rndSHA256 = get_random_SHA256();
//
//   String headerType = "content-type";
//   String header = "multipart/form-data; boundary=----" + rndSHA256;
//
//   String uuidEncapseld = "multipart/form-data; boundary=----"+rndSHA256+"\n\r------"+rndSHA256+"\r\nContent-Disposition: form-data; name=\"nfc_tag\"\r\n\r\n"+UUID+"\r\n------"+rndSHA256+"--";
//   String body = uuidEncapseld;
//   httpRequest(path, headerType, header,  body);
//
//   //Post UUID and recieve TDAT1 Token while Yield() with timeout
//   //return TDAT1
//   return true;
// }
//
//
// bool door_acces_controll_phase_2(String UDID, String TDAT)
// {
//   //String rndStr = get_random_SHA256();
//   //void SHA256::reset()
//   //void SHA256::update(const void *data, size_t len)
//   //evtl void SHA256::finalize(void *hash, size_t len
//
//   //Post SHA256 Hashed UDID with UUID and TDAT2
//   //recieve encrypted AES Encryption(NFC_TAG) key while Yield() with timeout
//   //decrypt encrypted AES Encryption(NFC_TAG) Key
//
//   // byte httpRequestResponseValue[] =
//   // AES aes128 = AES();
//   // //    bool SetKeyData(const byte* u8_Key, int s32_KeySize, byte u8_Version);
//   // //                    //UDID key           len(DIDI key) ,     (0) //erster verdacht aber nicht wirklich gewust DESFireKey() wird auch so initalisiert
//   // DESFireCipher decEncFlag = DESFireCipher.KEY_DECIPHER;
//   // aes128.SetKeyData(uUDIDkey, len(uDidkey), decEncFlag);
//   // //    bool CryptDataBlock(byte* u8_Out, const byte* u8_In, DESFireCipher e_Cipher);
//   // //                          retval           inval        DESFireCipher (0==KEY_ENCIPHER, 1==KEY_DECIPHER)
//   // aes128.CryptDataBlock(nfcAESKey, httpRequestResponseValue, decEncFlag );
//   // //return NFC_Tag key
//   return true;
// }
//
// bool door_acces_controll_phase_3(String UTID, String UUID)
// {
//   //POST AES encrypted(UTID) with Salt , UUID and TDAT3
//   //and recieve Acces(True//False) while Yield() with timeout
//   //light the led or not
//   int i = 1;
//   return true;
// }

// ############# HTTP REQUEST ################ //
// void httpRequest(String path, String headerType, String header, String body)
// {
//   String payload = makeRequest2(path, headerType, header, body);
//
//   if (!payload) {
//     return;
//   }
//   Serial.println("##[RESULT]## ==> " + payload);
// }
//
// String get_random_SHA256()
// {
//   String dateTimeStr = "";
//   //Create a DateTime object from the current time
//
//   //DateTime dt = DateTime();
//   //dt(rtc.makeDateTime(rtc.now().getEpoch()));
//   //Convert it to a String
//   //dt.addToString(dateTimeStr);
//
//   SHA256 sha256Hash = SHA256();
//   String toHash = dateTimeStr;
//   char charBuff[toHash.length()];
//   toHash.toCharArray(charBuff, toHash.length());
//   sha256Hash.update(charBuff , toHash.length());
//   sha256Hash.finalize(charBuff , ((size_t)toHash.length()));
//   return charBuff;
// }
// String makeRequest2(String path, String headerType, String header, String body)
// {
//
//
//
//   http.begin(BASE_URL + path);
//
//   //http.addParameter("multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW", "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"nfc_tag\"\r\n\r\nA9:CD:85:89\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--");
//   http.addHeader(headerType, header);
//   Serial.println(http.getString());
//
//   int httpCode = http.POST(body);
//
//   if (httpCode < 0) {
//     Serial.println("request error - " + httpCode);
//     Serial.println(http.errorToString(httpCode));
//
//     return http.errorToString(httpCode);
//
//   }
//   Serial.println(http.getString());
//
//   if (httpCode != HTTP_CODE_OK) {
//     return http.errorToString(httpCode);
//   }
//   return "";
// }
