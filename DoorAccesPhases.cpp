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
  if(String(udid).length()<=32)
    memcpy(UDID, udid, String(udid).length()+1);
  else
    Serial.println("udid wrong length");
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
    memcpy(nfcUUID, uuid, String(uuid).length());
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
          if((String(tdatArr).length()) ==256)
            memcpy(httpTDAT, tdatArr, String(tdatArr).length()+1);
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
    Serial.println("going to print repo");
    Serial.println(httpRespo);
    return true;
  }
}
bool DoorAccesPhases::Phase2()
{
  String path = "NFCDoorAcContPhase2/";
  unsigned char sha256length = 32;
  byte sha256Buffer[65] ="";
  char keyHash[65] ="";
  unsigned int plainUDID_TDATlength = String(UDID).length()+String(httpTDAT).length();
  char plainUDID_TDATbuffer[plainUDID_TDATlength+1];
  memcpy(&plainUDID_TDATbuffer[0], httpTDAT, String(httpTDAT).length());
  memcpy(&plainUDID_TDATbuffer[String(httpTDAT).length()], UDID,String(UDID).length()+1);


  // Serial.println("own UDID");
  // Serial.println(UDID);
  // Serial.println("\n\rplainUDID_TDDATbuffer");
  // Serial.println(plainUDID_TDATbuffer);

  sha256Calc(plainUDID_TDATbuffer, sha256Buffer, sha256length);

  Serial.println("looped output sha256Buffer HEX");
  for (unsigned int i = 0 ; i<32; i++)
      sprintf(&keyHash[i*2], "%02X",sha256Buffer[i]);

  Serial.println("\n\r");
  Serial.println("println keyHash");

  Serial.println(keyHash);

  HTTPClient http;
  String headerType = "content-type";
  String hexDigStr =  getRnd32hexDigString();
  String boundary = "--------------------------" + hexDigStr;
  String headerStr = "multipart/form-data; boundary=" + boundary;
  String content1  = "--"+boundary+"\r\n"+"Content-Disposition: form-data; name=\"userKeys\"\r\n\r\n"+String(nfcUUID)+"\r\n";
  String content2  = "--"+boundary+"\r\n"+"Content-Disposition: form-data; name=\"keyHash\"\r\n\r\n"+String(keyHash)+"\r\n"+"--"+boundary+"--\r\n";

  String body = content1 +content2;


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
    Serial.println(httpRespo);
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
    SHA256 shaHaschen = SHA256();
    shaHaschen.doUpdate(strInBuf);
    shaHaschen.doFinal(byteOutBuf);
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
