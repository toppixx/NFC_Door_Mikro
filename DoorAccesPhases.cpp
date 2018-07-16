#include "DoorAccesPhases.h"
//#include "AES.h"
#include "Crypto.h"
#include "Utils.h"
#include <ESP8266HTTPClient.h>
#include "ArduinoJson.h"
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

void DoorAccesPhases::init(char* udid)
{
  char freeEr16[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  char freeEr32[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  if(strlen(udid)<=32)
  {
    memcpy(UDID, udid, strlen(udid));
    memcpy(httpAESEncryptionKey, udid, AES_IV_LENGTH);
  }
  else
    Serial.println("udid wrong length");
  char keyHash[65] = "";
  for (unsigned int i = 0 ; i<32; i++)
      sprintf(&keyHash[i*2], "%02X",UDID[i]);
  Serial.println("UDID");
  Serial.println(keyHash);
  memcpy(nfcUUID, freeEr32, 33);
  memcpy(nfcAESEncryptionKey, freeEr16, 17);
  memcpy(nfcAESIV, freeEr16, 17);
  memcpy(nfcDataLoad, freeEr32, 33);
  httpBaseURL = "";
  memcpy(httpTDAT, freeEr32, 33);
  memcpy(httpAESIV, freeEr16, 17);
  memcpy(httpAESEncryptionKey, freeEr16, 17);
}

/*for the future not implemented at server yet*/
// unsigned char rndsha256Length = 32;
// unsigned char rndsha256Buffer[32] ="";
// getRndSha256(rndsha256Buffer, rndsha256Length);
//
// unsigned char sha256UUIDLength = 32;
// unsigned char sha256UUIDBuffer[32] = "";
//
// unsigned char shaUUIDplainLength = 64;
// unsigned char shaUUIDplainTxt[64] =  "";
// memcpy(&shaUUIDplainTxt[0],rndsha256Buffer,rndsha256Length);
// memcpy(&shaUUIDplainTxt[32],nfcUUID, nfcUUIDLength);
// Sha256Class sha256Hasher = Sha256Class();
// sha256Hasher.init();
// sha256Hasher.initHmac((const unsigned char*) shaUUIDplainTxt, shaUUIDplainLength);
// memcpy(sha256UUIDBuffer,sha256Hasher.resultHmac(), sha256UUIDLength);
//sha256UUIDBuffer need to be send to server with rndsha256Buffer

bool DoorAccesPhases::Phase1(char* uuid, String baseURL)
{
  httpBaseURL = baseURL;

  if(String(uuid).length()<=32)
    memcpy(nfcUUID, uuid, strlen(uuid));
  else
  {
    Serial.println("uuid to long");
    return false;
  }
  String path = "NFCDoorAcContPhase1/";
  String hexDigStr =  getRnd32hexDigString();
  String headerType = "content-type";
  String boundary = "--------------------------" + hexDigStr;
  String headerStr = "multipart/form-data; boundary=" + boundary;
  //String body = "multipart/form-data; boundary=----"+hexDigStr+"\n\r------"+hexDigStr+"\r\nContent-Disposition: form-data; name=\"userKeys\"\r\n\r\n"+nfcUUID+"\r\n------"+hexDigStr+"--";
  String body  = "--"+boundary+"\r\n"+"Content-Disposition: form-data; name=\"userKeys\"\r\n\r\n"+nfcUUID+"\r\n"+"--"+boundary+"--\r\n";
  HTTPClient http;
  http.begin(baseURL + path);
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
    //Serial.println("get String()");
    String httpRespo = http.getString();

    //Serial.println(httpRespo);
    Serial.println("going to Json");
    if(httpRespo.length()<400)
    {
      StaticJsonBuffer<400> jsonBuffer;
      JsonObject& jsonObject = jsonBuffer.parseObject(httpRespo);
      Serial.println("Jsoned");

      if (!jsonObject.success())
      {
        Serial.println("parseObject() failed");
        return false;
      }
      else
      {
        const char* tdatArr = jsonObject["returnToken"];
        //Serial.println(tdatArr);
        Serial.println("get returnToken");
        if (tdatArr)
        {
          if((String(tdatArr).length()) ==32)
            memcpy(httpTDAT, tdatArr, strlen(tdatArr)+1);
          else
            Serial.println("TDAT wrong size");
          }
        else
        Serial.println("couldnt get returnToken");
      }
      }
      else
      {
      Serial.println("jsonBuffer to small");
      return false;
    }
    Serial.println("going to print respons");
    Serial.println(httpRespo);
    return true;
  }
}
bool DoorAccesPhases::Phase2()
{


  String path = "NFCDoorAcContPhase2/";
  unsigned char sha256length = 32;
  uint8_t sha256Buffer[65] ="";
  char keyHash[65] ="";
  uint8_t plainUDID_TDATlength = UDIDLen +httpTDATLen;
  char plainUDID_TDATbuffer[plainUDID_TDATlength+1];
  memcpy(&plainUDID_TDATbuffer[0], httpTDAT, httpTDATLen);
  memcpy(&plainUDID_TDATbuffer[httpTDATLen-1], UDID, UDIDLen);
  Serial.println((char*)UDID);
  Serial.println((char*)httpTDAT);

  Serial.println(plainUDID_TDATbuffer);

  sha256Calc(plainUDID_TDATbuffer, sha256Buffer, sha256length);

  Serial.println("looped output sha256Buffer HEX");
  for (unsigned int i = 0 ; i<32; i++)
      sprintf(&keyHash[i*2], "%02X",sha256Buffer[i]);

  Serial.println("\n\r");
  Serial.println("println keyHash");

  Serial.println(keyHash);

  String TDAT2 = "TDATtest";
  HTTPClient http;
  String headerType = "content-type";
  String hexDigStr =  getRnd32hexDigString();
  String boundary = "--------------------------" + hexDigStr;
  String headerStr = "multipart/form-data; boundary=" + boundary;
  String content1  = "--"+boundary+"\r\n"+"Content-Disposition: form-data; name=\"userKeys\"\r\n\r\n"+String(nfcUUID)+"\r\n";
  String content2  = "--"+boundary+"\r\n"+"Content-Disposition: form-data; name=\"keyHash\"\r\n\r\n"+String(keyHash)+"\r\n";
  String contetn3 = "--"+boundary+"\r\n"+"Content-Disposition: form-data; name=\"TDAT2\"\r\n\r\n"+String(TDAT2)+"\r\n"+"--"+boundary+"--\r\n";
  String body = content1 +content2 +contetn3;


  http.begin(httpBaseURL + path);
  http.addHeader(headerType, headerStr);
  int httpCode = http.POST(body);
  if (httpCode < 0)
  {
    Serial.println("request error - " + httpCode);
    Serial.println(http.errorToString(httpCode));
    return false;
  }

    String httpRespo = http.getString();
    Serial.println("");
    Serial.println(httpRespo);
    Serial.println("");

    Serial.println("going to Json");
    if(httpRespo.length()<200)
    {
      StaticJsonBuffer<200> jsonBuffer;
      JsonObject& jsonObject = jsonBuffer.parseObject(httpRespo);
      Serial.println("Jsoned");

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
        const char* aseIV = jsonObject["iv"];

          Serial.println("get  iv");
          if (aseIV)
          {
            byte ivBuffer[AES_IV_LENGTH];
            bool sucConvAESIV = convertStringToByteArr(aseIV, ivBuffer, AES_IV_LENGTH);
            if(sucConvAESIV)
            {
              Serial.println("converted IV");
              memcpy(httpAESIV, ivBuffer, AES_IV_LENGTH);
              printBlock(httpAESIV, AES_IV_LENGTH);
              Serial.println("(char*)httpAESIV");
              Serial.println((char*)httpAESIV);
            }
            else
            {
              Serial.println("converting iv failed");
              return false;
            }
          }
          else
          {
            Serial.println("couldnt get iv");
            return false;
          }
          //Serial.println(tdatArr);
          Serial.println("get cypher");
          if (aesCypher)
          {
              Serial.println("aseCypher Text");
              Serial.println(aesCypher);
              Serial.println("aesCypher Len");
              Serial.println(strlen(aesCypher));
              uint8_t cpyheredTextLen = strlen(aesCypher);
              uint8_t cypheredText[cpyheredTextLen];
              uint8_t cypherLen = cpyheredTextLen/2;
              uint8_t cypher[cypherLen];
              bool succAEScypher = convertStringToByteArr(aesCypher, cypher, cypherLen);
              if( succAEScypher)
              {

                Serial.println("\n\rconverted cypher");
                //memcpy(cypheredText, cypherBuffer, cypherLen);
                printBlock(cypher,cypherLen);
                //Serial.println((char*)cypheredText);

                uint8_t * keyEncrypt = UDID;
                char * udid = "cKeycKeycKeycKey";
                Serial.println("strlen(udid)");
                Serial.println(strlen(udid));
                memcpy(keyEncrypt, udid, strlen(udid));
                Serial.println("cypher");
                printBlock(cypher, 16);
                //int decodedSize = cpyheredTextLen;
                //int decryptedSize = decodedSize - AES_KEY_LENGTH - SHA256HMAC_SIZE;
                char decrypted[16];
                //int decodedSize = ivEncryptedHmacSize;
                //uint8_t* decoded = ivEncryptedHmac;
                Serial.println("keyEncrypt encryption Key");
                //Serial.println((char*)keyEncrypt);
                printBlock(keyEncrypt,16);
                Serial.println("httpAESIV");
                //Serial.println((char*)httpAESIV);
                printBlock(httpAESIV, 16);
                Serial.println("cypher");
                printBlock(cypher, 16);
                AES aesDecryptor(keyEncrypt, httpAESIV, AES::AES_MODE_128, AES::CIPHER_DECRYPT);


                //Serial.println(strlen(cypher));
                aesDecryptor.process((uint8_t*)cypher, (uint8_t*)decrypted, AES_KEY_LENGTH);

                Serial.printf("Decrypted Packet HEX (%d bytes)", AES_KEY_LENGTH);
                printBlock((uint8_t*)decrypted, AES_KEY_LENGTH);

                Serial.printf("Decrypted Packet (%d bytes):\n",  AES_KEY_LENGTH);
                Serial.println(decrypted);

              }
              else
              {
                Serial.println("converting cypher failed");
                return false;
              }
              /*starting decryption*/
              // uint8_t * keyEncrypt = UDID


              Serial.println("should be");
              Serial.println("32 48 4d 79 62 79 54 78 78 56 48 46 6e 36 45 58");
              Serial.println("last was: B6 27 C7 94 44 27 17 E7 7E F8 EC 46 40 C9 82 3E");
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

    // Serial.println("looped httpAESIV");
    // for (unsigned int i = 0 ; i<16; i++)
    //     sprintf(&keyHash[i*2], "%02X",httpAESIV[i]);
    //
    // Serial.println("\n\r");
    // Serial.println("println httpAESIV");
    // Serial.println(keyHash);
    //
    // for (unsigned int i = 0 ; i<32; i++)
    //     sprintf(&keyHash[i*2], "%02X",httpAESEncryptionKey[i]);
    //
    // Serial.println("\n\r");
    // Serial.println("AESEncryptedEncryptionKey");
    //
    // Serial.println(keyHash);
    //
    // for (unsigned int i = 0 ; i<32; i++)
    //     sprintf(&keyHash[i*2], "%02X",UDID[i]);
    // Serial.println("UDID");
    // Serial.println(keyHash);
    // Serial.println(keyHash);

    // AES aesDecryptor = AES((uint8_t*)UDID, (uint8_t*)httpAESIV, AES::AES_MODE_128, AES::CIPHER_DECRYPT);
    // aesDecryptor.process((uint8_t*)cypheredText, (uint8_t*)nfcAESIV,16);
    // Serial.println("Decrypted plain");
    // Serial.print(keyHash);
    // Serial.println("Decrypted as Hex");
    // for (unsigned int i = 0 ; i<32; i++)
    //     sprintf(&keyHash[i*2], "%02X",keyHash[i]);



    return true;
}
bool DoorAccesPhases::Phase3()
{
  bool retval = false;

  return retval;
}

void DoorAccesPhases::reset()
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

    int timeDisturbedStrlength = 70;
    char timeDisturbedStr[70] = "";
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
  byte hexDig32Buffer[33] ="";
  getRndSha256(hexDig32Buffer, hexDig32length);
  unsigned char buffer = 0;
  //Serial.println(hexDig32Buffer);

  //if (charArrOutLength<=32)
  //{
  char bufferStr[2]="";
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
  if( byteArrOutLength>=String(input).length()/2)
  {
    for(byte i = 0;i< String(input).length(); i=i+4)
    {
      byteArrOutBuff[i/2] = convertCharToHex(input[i])*16;
      byteArrOutBuff[i/2] += convertCharToHex(input[i+1]);
      byteArrOutBuff[i/2+1] = convertCharToHex(input[i+2])*16;
      byteArrOutBuff[i/2+1] += convertCharToHex(input[i+3]);
      Serial.print(input[i]); Serial.print(input[i+1]); Serial.print(input[i+2]); Serial.print(input[i+3]);
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
