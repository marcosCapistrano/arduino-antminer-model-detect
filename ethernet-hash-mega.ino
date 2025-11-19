/*
 * Antminer Discovery and Display System with DHCP Server
 *
 * Hardware:
 * - Arduino Mega 2560 (8KB RAM)
 * - W5100 Ethernet Shield
 * - 16x2 LCD Display (Parallel connection)
 *
 * Features:
 * - Acts as DHCP server to assign IP to Antminer (192.168.1.100)
 * - Arduino configured with static IP (192.168.1.1)
 * - Discovers Antminer via vnish-api
 * - Displays miner model and IP on LCD
 * - Direct connection: Arduino <-> Antminer (no router needed)
 *
 * Network Configuration:
 * - Arduino IP: 192.168.1.1
 * - Antminer IP (assigned via DHCP): 192.168.1.100
 * - Subnet: 255.255.255.0
 *
 * Pin Configuration (Arduino Mega):
 * - Ethernet Shield: Uses SPI pins 50-53 (MISO, MOSI, SCK, SS)
 * - LCD RS: Pin 9
 * - LCD EN: Pin 8
 * - LCD D4-D7: Pins 7, 6, 5, 3
 */

#include <SPI.h>
#include <Ethernet.h>
#include <EthernetUdp.h>
#include <LiquidCrystal.h>
#include <ArduinoJson.h>

// ===== CONFIGURATION =====

// LCD Pin Configuration (avoiding Ethernet shield pins 50, 51, 52, 53)
const int LCD_RS = 9;
const int LCD_EN = 8;
const int LCD_D4 = 7;
const int LCD_D5 = 6;
const int LCD_D6 = 5;
const int LCD_D7 = 3;

// Network Configuration
byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };
IPAddress arduinoIP(192, 168, 1, 1);
IPAddress subnet(255, 255, 255, 0);
IPAddress gateway(192, 168, 1, 1);
IPAddress dns(192, 168, 1, 1);
IPAddress antminerIP(192, 168, 1, 100);

// DHCP Server Configuration
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define DHCP_MAGIC_COOKIE 0x63825363

// DHCP Message Types
#define DHCP_DISCOVER 1
#define DHCP_OFFER 2
#define DHCP_REQUEST 3
#define DHCP_ACK 5

// DHCP Options
#define DHCP_OPT_SUBNET_MASK 1
#define DHCP_OPT_ROUTER 3
#define DHCP_OPT_DNS 6
#define DHCP_OPT_REQUESTED_IP 50
#define DHCP_OPT_LEASE_TIME 51
#define DHCP_OPT_MSG_TYPE 53
#define DHCP_OPT_SERVER_ID 54
#define DHCP_OPT_END 255

// DHCP Packet Structure
struct DHCPPacket {
  uint8_t op;
  uint8_t htype;
  uint8_t hlen;
  uint8_t hops;
  uint32_t xid;
  uint16_t secs;
  uint16_t flags;
  uint8_t ciaddr[4];
  uint8_t yiaddr[4];
  uint8_t siaddr[4];
  uint8_t giaddr[4];
  uint8_t chaddr[16];
  uint8_t sname[64];
  uint8_t file[128];
  uint8_t options[312];
};

// Discovery Configuration
const int DISCOVERY_RETRIES = 5;
const unsigned long RETRY_DELAY = 2000;  // 2 seconds between retries

// API Configuration
const int HTTP_PORT = 80;
const unsigned long HTTP_TIMEOUT = 5000;

// ===== GLOBAL OBJECTS =====
LiquidCrystal lcd(LCD_RS, LCD_EN, LCD_D4, LCD_D5, LCD_D6, LCD_D7);
EthernetClient client;
EthernetUDP udpServer;

// ===== STATE VARIABLES =====
bool minerFound = false;
IPAddress minerIP;
String minerModel = "";
unsigned long lastConnectionCheck = 0;
int consecutiveFailures = 0;
const int MAX_FAILURES = 1;
const unsigned long CHECK_INTERVAL = 1000;  // Check every 10 seconds

// ===== GLOBAL BUFFERS =====
uint8_t dhcpBuffer[548];

// ===== MEMORY MONITORING =====
int getFreeRAM() {
  extern int __heap_start, *__brkval;
  int v;
  return (int) &v - (__brkval == 0 ? (int) &__heap_start : (int) __brkval);
}

// ===== DISPLAY FUNCTIONS =====
void displayMessage(const String& line1, const String& line2) {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print(line1);
  lcd.setCursor(0, 1);
  lcd.print(line2);

  // Also print to serial for debugging
  Serial.print(F("[LCD] "));
  Serial.print(line1);
  Serial.print(F(" | "));
  Serial.println(line2);
}

// ===== NETWORK FUNCTIONS =====
bool initializeNetwork() {
  Serial.println(F("\n=== Network Initialization ==="));
  displayMessage("Inicializando", "Rede...");

  Ethernet.begin(mac, arduinoIP, dns, gateway, subnet);
  delay(1500);

  char ipStr[16];
  IPAddress ip = Ethernet.localIP();
  sprintf(ipStr, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);

  Serial.print(F("Arduino IP: "));
  Serial.println(ipStr);

  displayMessage("Arduino IP:", ipStr);
  delay(2000);

  if (udpServer.begin(DHCP_SERVER_PORT)) {
    Serial.println(F("DHCP server started on port 67"));
    displayMessage("Servidor DHCP", "Pronto");
    delay(1500);
    return true;
  } else {
    Serial.println(F("ERROR: Failed to start DHCP server"));
    displayMessage("Servidor DHCP", "FALHOU!");
    return false;
  }
}

// ===== DHCP SERVER FUNCTIONS =====
void writeDHCPOption(uint8_t* buffer, int& pos, uint8_t option, uint8_t length, const uint8_t* data) {
  buffer[pos++] = option;
  buffer[pos++] = length;
  for (int i = 0; i < length; i++) {
    buffer[pos++] = data[i];
  }
}

void sendDHCPResponse(DHCPPacket& request, uint8_t msgType) {
  memset(dhcpBuffer, 0, sizeof(dhcpBuffer));

  // BOOTP header
  dhcpBuffer[0] = 2;  // BOOTREPLY
  dhcpBuffer[1] = 1;  // Ethernet
  dhcpBuffer[2] = 6;
  dhcpBuffer[3] = 0;

  memcpy(&dhcpBuffer[4], &request.xid, 4);
  dhcpBuffer[8] = 0;
  dhcpBuffer[9] = 0;
  memcpy(&dhcpBuffer[10], &request.flags, 2);

  // Assign Antminer IP
  dhcpBuffer[16] = antminerIP[0];
  dhcpBuffer[17] = antminerIP[1];
  dhcpBuffer[18] = antminerIP[2];
  dhcpBuffer[19] = antminerIP[3];

  // Server IP
  dhcpBuffer[20] = arduinoIP[0];
  dhcpBuffer[21] = arduinoIP[1];
  dhcpBuffer[22] = arduinoIP[2];
  dhcpBuffer[23] = arduinoIP[3];

  memcpy(&dhcpBuffer[28], request.chaddr, 16);

  // Magic cookie
  dhcpBuffer[236] = 0x63;
  dhcpBuffer[237] = 0x82;
  dhcpBuffer[238] = 0x53;
  dhcpBuffer[239] = 0x63;

  // DHCP Options
  int optPos = 240;

  uint8_t msgTypeData[] = { msgType };
  writeDHCPOption(dhcpBuffer, optPos, DHCP_OPT_MSG_TYPE, 1, msgTypeData);

  uint8_t serverID[] = { arduinoIP[0], arduinoIP[1], arduinoIP[2], arduinoIP[3] };
  writeDHCPOption(dhcpBuffer, optPos, DHCP_OPT_SERVER_ID, 4, serverID);

  uint8_t leaseTime[] = { 0x00, 0x00, 0x0E, 0x10 };
  writeDHCPOption(dhcpBuffer, optPos, DHCP_OPT_LEASE_TIME, 4, leaseTime);

  uint8_t subnetMask[] = { subnet[0], subnet[1], subnet[2], subnet[3] };
  writeDHCPOption(dhcpBuffer, optPos, DHCP_OPT_SUBNET_MASK, 4, subnetMask);

  uint8_t router[] = { gateway[0], gateway[1], gateway[2], gateway[3] };
  writeDHCPOption(dhcpBuffer, optPos, DHCP_OPT_ROUTER, 4, router);

  uint8_t dnsServer[] = { dns[0], dns[1], dns[2], dns[3] };
  writeDHCPOption(dhcpBuffer, optPos, DHCP_OPT_DNS, 4, dnsServer);

  dhcpBuffer[optPos++] = DHCP_OPT_END;

  IPAddress broadcastIP(255, 255, 255, 255);
  udpServer.beginPacket(broadcastIP, DHCP_CLIENT_PORT);
  udpServer.write(dhcpBuffer, optPos);
  udpServer.endPacket();

  Serial.print(F("  -> Sent DHCP "));
  Serial.print(msgType == DHCP_OFFER ? F("OFFER") : F("ACK"));
  Serial.print(F(" (IP: "));
  Serial.print(antminerIP[0]); Serial.print(F("."));
  Serial.print(antminerIP[1]); Serial.print(F("."));
  Serial.print(antminerIP[2]); Serial.print(F("."));
  Serial.print(antminerIP[3]); Serial.println(F(")"));
}

void processDHCP() {
  int packetSize = udpServer.parsePacket();
  if (packetSize <= 0) return;

  Serial.print(F("\n[DHCP] Packet received ("));
  Serial.print(packetSize);
  Serial.println(F(" bytes)"));

  int len = udpServer.read(dhcpBuffer, sizeof(dhcpBuffer));
  if (len < 240) {
    Serial.println(F("  -> Packet too small, ignoring"));
    return;
  }

  // Check magic cookie
  if (dhcpBuffer[236] != 0x63 || dhcpBuffer[237] != 0x82 ||
      dhcpBuffer[238] != 0x53 || dhcpBuffer[239] != 0x63) {
    Serial.println(F("  -> Invalid magic cookie"));
    return;
  }

  // Parse DHCP message type
  uint8_t dhcpMsgType = 0;
  int i = 240;
  while (i < len && dhcpBuffer[i] != DHCP_OPT_END) {
    uint8_t option = dhcpBuffer[i++];
    if (option == 0) continue;
    uint8_t optLen = dhcpBuffer[i++];
    if (option == DHCP_OPT_MSG_TYPE && optLen == 1) {
      dhcpMsgType = dhcpBuffer[i];
    }
    i += optLen;
  }

  DHCPPacket request;
  memcpy(&request, dhcpBuffer, min(len, (int)sizeof(DHCPPacket)));

  if (dhcpMsgType == DHCP_DISCOVER) {
    Serial.println(F("  -> DHCP DISCOVER"));
    displayMessage("DHCP: Antminer", "Pedindo IP...");
    sendDHCPResponse(request, DHCP_OFFER);
  } else if (dhcpMsgType == DHCP_REQUEST) {
    Serial.println(F("  -> DHCP REQUEST"));
    displayMessage("DHCP: Enviado", "IP 192.168.1.100");
    sendDHCPResponse(request, DHCP_ACK);
  }
}

// ===== CONNECTION MONITORING =====
bool isMinerStillConnected() {
  if (!minerFound) return false;

  // Try a simple HTTP HEAD request to check connectivity
  if (client.connect(minerIP, HTTP_PORT)) {
    client.println(F("HEAD /api/v1/info HTTP/1.1"));
    client.print(F("Host: "));
    client.print(minerIP[0]); client.print(F("."));
    client.print(minerIP[1]); client.print(F("."));
    client.print(minerIP[2]); client.print(F("."));
    client.println(minerIP[3]);
    client.println(F("Connection: close"));
    client.println();

    unsigned long timeout = millis();
    while (client.available() == 0) {
      if (millis() - timeout > 2000) {  // 2 second timeout
        client.stop();
        return false;
      }
    }
    client.stop();
    return true;
  }
  return false;
}

void handleDisconnect() {
  Serial.println(F("\n!!! CONNECTION LOST !!!"));
  displayMessage("Conexao", "Perdida!");
  delay(2000);

  // Reset state
  minerFound = false;
  minerModel = "";
  consecutiveFailures = 0;
  lastConnectionCheck = 0;

  Serial.println(F("Resetting... waiting for new connection"));
}

void waitForNewConnection() {
  displayMessage("Aguardando nova", "conexao");
  Serial.println(F("\n=== Waiting for New Connection ==="));

  // Wait for DHCP again
  Serial.println(F("DHCP wait (5s)..."));
  unsigned long dhcpStart = millis();
  while (millis() - dhcpStart < 5000) {
    processDHCP();
    delay(100);
  }

  // Try to discover miner
  Serial.println(F("Attempting discovery..."));
  if (discoverMiner()) {
    minerFound = true;
    displayMessage("Miner!", "Reconectado");
    delay(1500);
    displayMinerInfo();
    lastConnectionCheck = millis();
    consecutiveFailures = 0;
  } else {
    displayMessage("Nao encontrado", "Aguardando...");
    delay(2000);
  }
}

// ===== ANTMINER API FUNCTIONS =====
bool checkMinerAtIP(IPAddress ip) {
  char ipStr[16];
  sprintf(ipStr, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);

  if (client.connect(ip, HTTP_PORT)) {
    client.println(F("GET /api/v1/info HTTP/1.1"));
    client.print(F("Host: "));
    client.println(ipStr);
    client.println(F("Accept: application/json"));
    client.println(F("Connection: close"));
    client.println();

    unsigned long timeout = millis();
    while (client.available() == 0) {
      if (millis() - timeout > HTTP_TIMEOUT) {
        client.stop();
        return false;
      }
    }

    // Skip headers
    bool headersEnded = false;
    while (client.available() && !headersEnded) {
      String line = client.readStringUntil('\n');
      if (line == "\r" || line.length() == 0) {
        headersEnded = true;
      }
    }

    if (client.available()) {
      StaticJsonDocument<256> doc;
      DeserializationError error = deserializeJson(doc, client);
      client.stop();

      if (!error && (doc.containsKey("miner") || doc.containsKey("model"))) {
        minerModel = doc.containsKey("miner") ? doc["miner"].as<String>() : doc["model"].as<String>();
        minerIP = ip;
        Serial.print(F("  -> FOUND: "));
        Serial.println(minerModel);
        return true;
      }
    }
    client.stop();
  }
  return false;
}

bool discoverMiner() {
  Serial.println(F("\n=== Miner Discovery ==="));
  displayMessage("Procurando", "Antminer...");

  // Try DHCP assigned IP with retries (only check 192.168.1.100)
  for (int retry = 0; retry < DISCOVERY_RETRIES; retry++) {
    Serial.print(F("Checking 192.168.1.100 (attempt "));
    Serial.print(retry + 1);
    Serial.print(F("/"));
    Serial.print(DISCOVERY_RETRIES);
    Serial.print(F(")... "));

    if (checkMinerAtIP(antminerIP)) {
      return true;
    }

    Serial.println(F("Not found"));

    if (retry < DISCOVERY_RETRIES - 1) {
      Serial.print(F("Waiting "));
      Serial.print(RETRY_DELAY / 1000);
      Serial.println(F(" seconds..."));
      delay(RETRY_DELAY);
    }
  }

  Serial.println(F("\nMiner not found after all retries"));
  return false;
}

void displayMinerInfo() {
  char ipStr[16];
  sprintf(ipStr, "%d.%d.%d.%d", minerIP[0], minerIP[1], minerIP[2], minerIP[3]);

  lcd.clear();
  lcd.setCursor(0, 0);
  if (minerModel.length() > 16) {
    lcd.print(minerModel.substring(0, 16));
  } else {
    lcd.print(minerModel);
  }

  lcd.setCursor(0, 1);
  lcd.print(ipStr);

  Serial.println(F("\n=== MINER INFO ==="));
  Serial.print(F("Model: "));
  Serial.println(minerModel);
  Serial.print(F("IP: "));
  Serial.println(ipStr);
  Serial.println(F("=================="));
}

// ===== SETUP AND LOOP =====
void setup() {
  Serial.begin(115200);
  delay(100);

  Serial.println(F("\n\n================================"));
  Serial.println(F("  Antminer Discovery v2.0"));
  Serial.println(F("  Arduino Mega 2560"));
  Serial.println(F("================================"));

  lcd.begin(16, 2);
  displayMessage("Antminer", "Discovery v2.0");
  delay(2000);

  Serial.print(F("Free RAM: "));
  Serial.print(getFreeRAM());
  Serial.println(F(" bytes"));

  if (!initializeNetwork()) {
    Serial.println(F("\nFATAL: Network init failed"));
    while (1) delay(1000);
  }

  // Wait for DHCP
  displayMessage("Aguardando", "Antminer DHCP...");
  Serial.println(F("\n=== DHCP Wait (5s) ==="));
  Serial.println(F("Waiting for Antminer to request IP..."));

  unsigned long dhcpStart = millis();
  while (millis() - dhcpStart < 5000) {
    processDHCP();
    delay(100);
  }

  Serial.println(F("DHCP wait complete\n"));

  // Discover miner
  delay(1000);
  if (discoverMiner()) {
    minerFound = true;
    displayMessage("Miner!", "Carregando...");
    delay(1500);
    displayMinerInfo();
    lastConnectionCheck = millis();
  } else {
    displayMessage("Nao encontrado", "Checar cabo");
  }

  Serial.print(F("\nFree RAM at end: "));
  Serial.print(getFreeRAM());
  Serial.println(F(" bytes\n"));
  Serial.println(F("Setup complete"));
}

void loop() {
  // Always process DHCP requests
  processDHCP();
  Ethernet.maintain();

  // If no miner found, wait for new connection
  if (!minerFound) {
    waitForNewConnection();
    return;
  }

  // Check connection periodically
  if (millis() - lastConnectionCheck >= CHECK_INTERVAL) {
    lastConnectionCheck = millis();

    Serial.print(F("[Monitor] Checking connection... "));

    if (isMinerStillConnected()) {
      Serial.println(F("OK"));
      consecutiveFailures = 0;
    } else {
      consecutiveFailures++;
      Serial.print(F("FAILED ("));
      Serial.print(consecutiveFailures);
      Serial.print(F("/"));
      Serial.print(MAX_FAILURES);
      Serial.println(F(")"));

      if (consecutiveFailures >= MAX_FAILURES) {
        handleDisconnect();
      }
    }
  }

  delay(100);
}
