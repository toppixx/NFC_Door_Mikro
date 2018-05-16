/**************************************************************************/
/*!
    Connects to wifi and waits for an NFC tag with a specific UID.
    Sends a UDP packet if tag is found.
    This specific version is used to unloack a door, hence the unlock() function. (and the IPAddress object called doorIP)
    To enable debug message, define DEBUG in PN532/PN532_debug.h
  Runs on an ESP8266 (nodeMCU v0.9) connected to an adafruit NFC (PN532) shield
  HW setup:
  NFC   NodeMCU (ESP):
  SS (CS) D2    (GPIO4)
  IRQ     D3    (GPIO0) //anderen pin suchen wird für flash user button wifi reset benutzt
  RST     D4    (GPIO2)
  SCK     D5    (GPIO14)
  MISO    D6    (GPIO12)
  MOSI    D7    (GPIO13)

  Jumpers: SEL0=closed , SEL1=closed (set to SPI mode)
*/
/**************************************************************************/

#include <ESP8266WiFi.h>
#include <WiFiUdp.h>
#include <WiFiClient.h>
#include <WiFiManager.h>          //https://github.com/tzapu/WiFiManager
#include <ArduinoOTA.h>

#include <SPI.h>
#include <PN532_SPI.h>
#include <PN532.h>

#include <ESP8266mDNS.h>
#include <ESP8266HTTPClient.h>

#include <ESP8266Ping.h>

void unlock();
//userbutton reset for connecting to new WIFI
void hardwareReset();
void resetToFactoryDefaults();
void isrResetToFactoryDefaults(void);
const byte interruptPin = 0;
volatile boolean interruptUserButtonFlag = false;

//UDP stuff:
WiFiUDP Udp;
//const unsigned int remotePort = 1337;
const int UDP_PACKET_SIZE = 7; //change to whatever you need.
byte packetBuffer[ UDP_PACKET_SIZE ]; //buffer to hold outgoing packets

PN532_SPI pn532spi(SPI, D2);
PN532 nfc(pn532spi);

//WIFI Http stuff
WiFiClient client;
HTTPClient http;
char strBuffer[16];
char IP[4] = {192,168,43,173};
String BASE_URL = "";
void httpRequest(String path, String body);

void configModeCallback (WiFiManager *myWiFiManager) {
  Serial.println("Entered config mode");
  Serial.println("AP: " + myWiFiManager->getConfigPortalSSID());
  Serial.println("IP: " + WiFi.softAPIP().toString());
}


void setup(void) {
  sprintf(strBuffer,"%d.%d.%d.%d",IP[0], IP[1], IP[2], IP[3]);
  BASE_URL = "http://"+String(strBuffer)+"/";

  //setup user button to give the posibility to reset wifi stack and do a new connection over the web interface.
  pinMode(interruptPin, INPUT_PULLUP);
  attachInterrupt(digitalPinToInterrupt(interruptPin), isrResetToFactoryDefaults, FALLING);
  WiFi.hostname("ESPNFC");

  //WiFi.persistent(false);
  //WiFi.mode(WIFI_STA); //prevent random APs from forming?!

  Serial.begin(115200);
  Serial.println("Hello!");
  Serial.println(BASE_URL);

  //WiFiManager
  //Local intialization. Once its business is done, there is no need to keep it around
  WiFiManager wifiManager;

  Serial.println("Connecting to wifi..");
  wifiManager.setAPCallback(configModeCallback); //set callback that gets called when connecting to previous WiFi fails, and enters Access Point mode
  wifiManager.setConnectTimeout(30); //try to connect to known wifis for a long time before defaulting to AP mode

  //fetches ssid and pass and tries to connect
  //if it does not connect it starts an access point with the specified name
  //here  "ESPNFC"
  //and goes into a blocking loop awaiting configuration

  if (!wifiManager.autoConnect("ESPNFC"))
   {     

      Serial.println("failed to connect and hit timeout");
      ESP.restart(); //reset and try again, or maybe put it to deep sleep
     
  }
  //OTA:
  // Port defaults to 8266
  // ArduinoOTA.setPort(8266);
  // Hostname defaults to esp8266-[ChipID]
  ArduinoOTA.setHostname("ESPNFC");
  // No authentication by default
  ArduinoOTA.setPassword((const char *)"1804020311");
  //ArduinoOTA.setPasswordHash((const char *)"77ca9ed101ac99e43b6842c169c20fda");

  ArduinoOTA.onStart([]() {
    Serial.println("OTA START!");
    delay(500);
  });

  ArduinoOTA.onEnd([]() {
    Serial.println("OTA End.. brace for reset");
    ESP.restart();
  });

  ArduinoOTA.onProgress([](unsigned int progress, unsigned int total) {
    Serial.printf("Progress: %u%%\r", (progress / (total / 100)));
    });

  ArduinoOTA.onError([](ota_error_t error) {
    String buffer=String("Error[") + String(error) + String("]: ");
    if (error == OTA_AUTH_ERROR) buffer+=String("Auth Failed");
    else if (error == OTA_BEGIN_ERROR) buffer+=String("Begin Failed");
    else if (error == OTA_CONNECT_ERROR) buffer+=String("Connect Failed");
    else if (error == OTA_RECEIVE_ERROR) buffer+=String("Receive Failed");
    else if (error == OTA_END_ERROR) buffer+=String("End Failed");

    Serial.println(buffer);
  });

  ArduinoOTA.begin();

  nfc.begin();

  uint32_t versiondata = nfc.getFirmwareVersion();
  if (! versiondata) {
    Serial.print("Didn't find PN53x board");
    while (1); // halt
  }

  // Got ok data, print it out!
  Serial.print("Found chip PN5"); Serial.println((versiondata>>24) & 0xFF, HEX);
  Serial.print("Firmware ver. "); Serial.print((versiondata>>16) & 0xFF, DEC);
  Serial.print('.'); Serial.println((versiondata>>8) & 0xFF, DEC);

  // Set the max number of retry attempts to read from a card
  // This prevents us from waiting forever for a card, which is
  // the default behaviour of the PN532.
  //nfc.setPassiveActivationRetries(0xFF);
  nfc.setPassiveActivationRetries(10);

  // configure board to read RFID tags
  nfc.SAMConfig();

  Serial.println("Ping on Ip to look if server is allive");
  IPAddress ip (IP[0],IP[1],IP[2], IP[3]); // The remote ip to ping
  bool ret = Ping.ping(ip);
  if(ret==true)
    Serial.println("Server available");
  else
    Serial.println("Cant reach server");
  Serial.println("Waiting for an ISO14443A card");
  Serial.println("\n-----------\n");
}

void loop(void) {

  boolean success;
  uint8_t uidLength;   // Length of the UID (4 or 7 bytes depending on ISO14443A card type)
  uint8_t uid[] = { 0, 0, 0, 0, 0, 0, 0 };  // Buffer to store the returned UID

  // Wait for an ISO14443A type cards (Mifare, etc.).  When one is found
  // 'uid' will be populated with the UID, and uidLength will indicate
  // if the uid is 4 bytes (Mifare Classic) or 7 bytes (Mifare Ultralight)
  success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, &uid[0], &uidLength);

  if (success) {
    Serial.println("Found a card!");
    Serial.print("UID Length: ");
    Serial.print(uidLength, DEC);
    Serial.println(" bytes");
    Serial.print("UID Value: ");

    for (uint8_t i=0; i < uidLength; i++)
    {
      Serial.print(" 0x");
      Serial.print(uid[i], HEX);
    }
    Serial.println("");

    // wait until the card is taken away
    while (nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, &uid[0], &uidLength)) yield(); //let ESPcore handle wifi stuff

        char buffer[] = "1234567";
        String body;
        
        if(uidLength==4)
          {
            sprintf(buffer, "%02X:%02X:%02X:%02X",uid[0],uid[1],uid[2],uid[3]);
            body = String(buffer);
          }
        if(uidLength==7)
           {
            sprintf(buffer, "%02X:%02X:%02X:%02X%02X:%02X:%02X",uid[0],uid[1],uid[2],uid[3],uid[4],uid[5],uid[6]); 
            body = String(buffer);
           }
        if(body)
          {
            body = String("form-data; name=")+String('"')+String("nfc_tag")+String('"')+String("\r\n\r\n")+String(buffer);
            Serial.println(body);
            String path = "access/";
            httpRequest(path, body);
          }
        delay(500); //avoid  flooding
    
  Serial.println("\n-----------\n");
  
  //check if button was pressed. that will reset the wifi to default and api mode.
  if (interruptUserButtonFlag) resetToFactoryDefaults();
  }
  else yield(); // PN532 probably timed out waiting for a card.. let's let the ESPcore handle wifi stuff


}


// ############# HTTP REQUEST ################ //

void httpRequest(String path, String body)
{
  String payload = makeRequest(path, body);

  if (!payload) {
    return;
  }
  Serial.println("##[RESULT]## ==> " + payload);
}

String makeRequest(String path, String body)
{
  http.begin(BASE_URL + path);
  http.addHeader("Authorization", "Token b454942f1ecdc11fc8c1b1a3c2c3b8c5203d805f");
  body = "multipart/form-data; boundary=----NFCtagHandleBoundary15gabfalsd091590a\n\r------NFCtagHandleBoundary15gabfalsd091590a\r\nContent-Disposition: form-data; name=\"nfc_tag\"\r\n\r\nA9:CD:85:89\r\n------NFCtagHandleBoundary15gabfalsd091590a--";
  http.addHeader("content-type", "multipart/form-data; boundary=----NFCtagHandleBoundary15gabfalsd091590a");
  //http.addParameter("multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW", "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"nfc_tag\"\r\n\r\nA9:CD:85:89\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--");
  Serial.println(http.getString());

  int httpCode = http.POST(body);

  if (httpCode < 0) {
    Serial.println("request error - " + httpCode);
    Serial.println(http.errorToString(httpCode));

    return http.errorToString(httpCode);

  }
  Serial.println(http.getString());

  if (httpCode != HTTP_CODE_OK) {
    return http.errorToString(httpCode);
  }
  return "";
}
//###############GET REQUEST#############
void httpGet(String path)
{
   http.begin(BASE_URL + path);
  http.addHeader("Authorization", "Token b454942f1ecdc11fc8c1b1a3c2c3b8c5203d805f");
  int httpCode = http.GET();
  
  return;
}

//code from https://github.com/tzapu/WiFiManager/issues/142
void resetToFactoryDefaults() {
  WiFi.disconnect();
  delay(3000);
  interruptUserButtonFlag = false;
}

void isrResetToFactoryDefaults(void) {
  Serial.println("Resetting to factory defaults");
  interruptUserButtonFlag = true;
}
