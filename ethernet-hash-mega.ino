/*
 * Antminer Discovery and Display System with DHCP Server
 *
 * Hardware:
 * - Arduino Mega 2560 (8KB RAM)
 * - W5100 Ethernet Shield
 * - 16x2 LCD Display (I2C interface)
 *
 * Features:
 * - Acts as DHCP server to assign IP to Antminer (192.168.1.100)
 * - Arduino configured with static IP (192.168.1.1)
 * - Discovers Antminer via vnish-api OR stock Bitmain firmware
 * - Supports HTTP Digest Authentication for stock firmware
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
 * - LCD I2C: SDA (A4), SCL (A5)
 */

#include <SPI.h>
#include <Ethernet.h>
#include <EthernetUdp.h>
#include <LiquidCrystal_I2C.h>
#include <Wire.h>
#include <ArduinoJson.h>

// Forward declaration for Arduino preprocessor
struct DHCPPacket;

// ===== EMBEDDED MD5 IMPLEMENTATION =====
// Minimal MD5 hash implementation for HTTP Digest Authentication
// Based on RFC 1321, optimized for Arduino (no dynamic memory allocation)

typedef struct {
  uint32_t state[4];
  uint32_t count[2];
  uint8_t buffer[64];
} MD5_CTX;

static const uint8_t PROGMEM md5_padding[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

#define MD5_F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define MD5_G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define MD5_H(x, y, z) ((x) ^ (y) ^ (z))
#define MD5_I(x, y, z) ((y) ^ ((x) | (~z)))
#define MD5_ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

#define MD5_FF(a, b, c, d, x, s, ac) { \
  (a) += MD5_F((b), (c), (d)) + (x) + (uint32_t)(ac); \
  (a) = MD5_ROTATE_LEFT((a), (s)); \
  (a) += (b); \
}
#define MD5_GG(a, b, c, d, x, s, ac) { \
  (a) += MD5_G((b), (c), (d)) + (x) + (uint32_t)(ac); \
  (a) = MD5_ROTATE_LEFT((a), (s)); \
  (a) += (b); \
}
#define MD5_HH(a, b, c, d, x, s, ac) { \
  (a) += MD5_H((b), (c), (d)) + (x) + (uint32_t)(ac); \
  (a) = MD5_ROTATE_LEFT((a), (s)); \
  (a) += (b); \
}
#define MD5_II(a, b, c, d, x, s, ac) { \
  (a) += MD5_I((b), (c), (d)) + (x) + (uint32_t)(ac); \
  (a) = MD5_ROTATE_LEFT((a), (s)); \
  (a) += (b); \
}

static void md5_decode(uint32_t *output, const uint8_t *input, uint32_t len) {
  for (uint32_t i = 0, j = 0; j < len; i++, j += 4)
    output[i] = ((uint32_t)input[j]) | (((uint32_t)input[j+1]) << 8) |
                (((uint32_t)input[j+2]) << 16) | (((uint32_t)input[j+3]) << 24);
}

static void md5_encode(uint8_t *output, const uint32_t *input, uint32_t len) {
  for (uint32_t i = 0, j = 0; j < len; i++, j += 4) {
    output[j] = (uint8_t)(input[i] & 0xff);
    output[j+1] = (uint8_t)((input[i] >> 8) & 0xff);
    output[j+2] = (uint8_t)((input[i] >> 16) & 0xff);
    output[j+3] = (uint8_t)((input[i] >> 24) & 0xff);
  }
}

static void md5_transform(uint32_t state[4], const uint8_t block[64]) {
  uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];
  md5_decode(x, block, 64);

  MD5_FF(a, b, c, d, x[ 0],  7, 0xd76aa478); MD5_FF(d, a, b, c, x[ 1], 12, 0xe8c7b756);
  MD5_FF(c, d, a, b, x[ 2], 17, 0x242070db); MD5_FF(b, c, d, a, x[ 3], 22, 0xc1bdceee);
  MD5_FF(a, b, c, d, x[ 4],  7, 0xf57c0faf); MD5_FF(d, a, b, c, x[ 5], 12, 0x4787c62a);
  MD5_FF(c, d, a, b, x[ 6], 17, 0xa8304613); MD5_FF(b, c, d, a, x[ 7], 22, 0xfd469501);
  MD5_FF(a, b, c, d, x[ 8],  7, 0x698098d8); MD5_FF(d, a, b, c, x[ 9], 12, 0x8b44f7af);
  MD5_FF(c, d, a, b, x[10], 17, 0xffff5bb1); MD5_FF(b, c, d, a, x[11], 22, 0x895cd7be);
  MD5_FF(a, b, c, d, x[12],  7, 0x6b901122); MD5_FF(d, a, b, c, x[13], 12, 0xfd987193);
  MD5_FF(c, d, a, b, x[14], 17, 0xa679438e); MD5_FF(b, c, d, a, x[15], 22, 0x49b40821);

  MD5_GG(a, b, c, d, x[ 1],  5, 0xf61e2562); MD5_GG(d, a, b, c, x[ 6],  9, 0xc040b340);
  MD5_GG(c, d, a, b, x[11], 14, 0x265e5a51); MD5_GG(b, c, d, a, x[ 0], 20, 0xe9b6c7aa);
  MD5_GG(a, b, c, d, x[ 5],  5, 0xd62f105d); MD5_GG(d, a, b, c, x[10],  9, 0x02441453);
  MD5_GG(c, d, a, b, x[15], 14, 0xd8a1e681); MD5_GG(b, c, d, a, x[ 4], 20, 0xe7d3fbc8);
  MD5_GG(a, b, c, d, x[ 9],  5, 0x21e1cde6); MD5_GG(d, a, b, c, x[14],  9, 0xc33707d6);
  MD5_GG(c, d, a, b, x[ 3], 14, 0xf4d50d87); MD5_GG(b, c, d, a, x[ 8], 20, 0x455a14ed);
  MD5_GG(a, b, c, d, x[13],  5, 0xa9e3e905); MD5_GG(d, a, b, c, x[ 2],  9, 0xfcefa3f8);
  MD5_GG(c, d, a, b, x[ 7], 14, 0x676f02d9); MD5_GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);

  MD5_HH(a, b, c, d, x[ 5],  4, 0xfffa3942); MD5_HH(d, a, b, c, x[ 8], 11, 0x8771f681);
  MD5_HH(c, d, a, b, x[11], 16, 0x6d9d6122); MD5_HH(b, c, d, a, x[14], 23, 0xfde5380c);
  MD5_HH(a, b, c, d, x[ 1],  4, 0xa4beea44); MD5_HH(d, a, b, c, x[ 4], 11, 0x4bdecfa9);
  MD5_HH(c, d, a, b, x[ 7], 16, 0xf6bb4b60); MD5_HH(b, c, d, a, x[10], 23, 0xbebfbc70);
  MD5_HH(a, b, c, d, x[13],  4, 0x289b7ec6); MD5_HH(d, a, b, c, x[ 0], 11, 0xeaa127fa);
  MD5_HH(c, d, a, b, x[ 3], 16, 0xd4ef3085); MD5_HH(b, c, d, a, x[ 6], 23, 0x04881d05);
  MD5_HH(a, b, c, d, x[ 9],  4, 0xd9d4d039); MD5_HH(d, a, b, c, x[12], 11, 0xe6db99e5);
  MD5_HH(c, d, a, b, x[15], 16, 0x1fa27cf8); MD5_HH(b, c, d, a, x[ 2], 23, 0xc4ac5665);

  MD5_II(a, b, c, d, x[ 0],  6, 0xf4292244); MD5_II(d, a, b, c, x[ 7], 10, 0x432aff97);
  MD5_II(c, d, a, b, x[14], 15, 0xab9423a7); MD5_II(b, c, d, a, x[ 5], 21, 0xfc93a039);
  MD5_II(a, b, c, d, x[12],  6, 0x655b59c3); MD5_II(d, a, b, c, x[ 3], 10, 0x8f0ccc92);
  MD5_II(c, d, a, b, x[10], 15, 0xffeff47d); MD5_II(b, c, d, a, x[ 1], 21, 0x85845dd1);
  MD5_II(a, b, c, d, x[ 8],  6, 0x6fa87e4f); MD5_II(d, a, b, c, x[15], 10, 0xfe2ce6e0);
  MD5_II(c, d, a, b, x[ 6], 15, 0xa3014314); MD5_II(b, c, d, a, x[13], 21, 0x4e0811a1);
  MD5_II(a, b, c, d, x[ 4],  6, 0xf7537e82); MD5_II(d, a, b, c, x[11], 10, 0xbd3af235);
  MD5_II(c, d, a, b, x[ 2], 15, 0x2ad7d2bb); MD5_II(b, c, d, a, x[ 9], 21, 0xeb86d391);

  state[0] += a; state[1] += b; state[2] += c; state[3] += d;
  memset(x, 0, sizeof(x));
}

void md5_init(MD5_CTX *ctx) {
  ctx->count[0] = ctx->count[1] = 0;
  ctx->state[0] = 0x67452301;
  ctx->state[1] = 0xefcdab89;
  ctx->state[2] = 0x98badcfe;
  ctx->state[3] = 0x10325476;
}

void md5_update(MD5_CTX *ctx, const uint8_t *input, uint32_t inputLen) {
  uint32_t i, index, partLen;
  index = (uint32_t)((ctx->count[0] >> 3) & 0x3F);
  if ((ctx->count[0] += ((uint32_t)inputLen << 3)) < ((uint32_t)inputLen << 3))
    ctx->count[1]++;
  ctx->count[1] += ((uint32_t)inputLen >> 29);
  partLen = 64 - index;
  if (inputLen >= partLen) {
    memcpy(&ctx->buffer[index], input, partLen);
    md5_transform(ctx->state, ctx->buffer);
    for (i = partLen; i + 63 < inputLen; i += 64)
      md5_transform(ctx->state, &input[i]);
    index = 0;
  } else {
    i = 0;
  }
  memcpy(&ctx->buffer[index], &input[i], inputLen - i);
}

void md5_final(uint8_t digest[16], MD5_CTX *ctx) {
  uint8_t bits[8], padding[64];
  uint32_t index, padLen;
  md5_encode(bits, ctx->count, 8);
  index = (uint32_t)((ctx->count[0] >> 3) & 0x3f);
  padLen = (index < 56) ? (56 - index) : (120 - index);
  memcpy_P(padding, md5_padding, padLen);
  md5_update(ctx, padding, padLen);
  md5_update(ctx, bits, 8);
  md5_encode(digest, ctx->state, 16);
  memset(ctx, 0, sizeof(*ctx));
}

// Simple wrapper to hash a string and return hex digest
void md5_hash(const char* input, char* outputHex) {
  MD5_CTX ctx;
  uint8_t digest[16];
  md5_init(&ctx);
  md5_update(&ctx, (const uint8_t*)input, strlen(input));
  md5_final(digest, &ctx);

  const char hexChars[] = "0123456789abcdef";
  for (int i = 0; i < 16; i++) {
    outputHex[i * 2] = hexChars[(digest[i] >> 4) & 0x0F];
    outputHex[i * 2 + 1] = hexChars[digest[i] & 0x0F];
  }
  outputHex[32] = '\0';
}
// ===== END MD5 IMPLEMENTATION =====

// ===== CONFIGURATION =====

// LCD I2C Configuration
// SDA: A4, SCL: A5 (hardware I2C pins)
// Common I2C addresses: 0x27 or 0x3F - adjust if display doesn't work
const uint8_t LCD_I2C_ADDRESS = 0x27;

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

// Stock Firmware Digest Authentication
// Default credentials for Bitmain stock firmware
const char* STOCK_USERNAME = "root";
const char* STOCK_PASSWORD = "root";
const char* STOCK_REALM = "antMiner Configuration";

// ===== GLOBAL OBJECTS =====
LiquidCrystal_I2C lcd(LCD_I2C_ADDRESS, 16, 2);
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

// ===== HTTP DIGEST AUTHENTICATION =====

// Extract nonce from WWW-Authenticate header
// Format: Digest realm="antMiner Configuration", nonce="abc123...", qop="auth"
bool extractNonce(const String& authHeader, char* nonceOut, int maxLen) {
  int nonceStart = authHeader.indexOf("nonce=\"");
  if (nonceStart < 0) return false;
  nonceStart += 7;  // Skip 'nonce="'

  int nonceEnd = authHeader.indexOf('"', nonceStart);
  if (nonceEnd < 0 || nonceEnd - nonceStart >= maxLen) return false;

  authHeader.substring(nonceStart, nonceEnd).toCharArray(nonceOut, maxLen);
  return true;
}

// Calculate HTTP Digest Authentication response
// response = MD5(MD5(username:realm:password):nonce:nc:cnonce:qop:MD5(method:uri))
String calculateDigestResponse(const char* username, const char* realm, const char* password,
                                const char* nonce, const char* nc, const char* cnonce,
                                const char* qop, const char* method, const char* uri) {
  char ha1[33], ha2[33], response[33];

  // HA1 = MD5(username:realm:password)
  String ha1Input = String(username) + ":" + String(realm) + ":" + String(password);
  md5_hash(ha1Input.c_str(), ha1);

  // HA2 = MD5(method:uri)
  String ha2Input = String(method) + ":" + String(uri);
  md5_hash(ha2Input.c_str(), ha2);

  // response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
  String responseInput = String(ha1) + ":" + String(nonce) + ":" + String(nc) + ":" +
                         String(cnonce) + ":" + String(qop) + ":" + String(ha2);
  md5_hash(responseInput.c_str(), response);

  return String(response);
}

// Build Authorization header for Digest auth
String buildDigestAuthHeader(const char* username, const char* realm, const char* nonce,
                              const char* uri, const char* response, const char* nc,
                              const char* cnonce, const char* qop) {
  return String("Digest username=\"") + username + "\", " +
         "realm=\"" + realm + "\", " +
         "nonce=\"" + nonce + "\", " +
         "uri=\"" + uri + "\", " +
         "qop=" + qop + ", " +
         "nc=" + nc + ", " +
         "cnonce=\"" + cnonce + "\", " +
         "response=\"" + response + "\"";
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

// Get terahash value for known miner models
// Returns hashrate in TH/s for SHA-256 miners
// For other algorithms, returns representative value (see comments)
int getTerahash(const String& model) {

  // ===== SHA-256 BITCOIN MINERS (S/T Series) =====

  // S23 Series (2025) - Latest generation
  if (model.indexOf("S23") >= 0) {
    if (model.indexOf("Hydro") >= 0 && model.indexOf("3U") >= 0) return 1160;
    if (model.indexOf("Hydro") >= 0) return 580;
    if (model.indexOf("IMM") >= 0) return 442;
    return 318;  // S23 Air
  }

  // S21 Series (2024) - check specific variants first
  if (model.indexOf("S21") >= 0) {
    if (model.indexOf("XP") >= 0 && model.indexOf("Hydro") >= 0) return 473;
    if (model.indexOf("XP") >= 0 && model.indexOf("Imm") >= 0) return 270;
    if (model.indexOf("XP") >= 0) return 270;
    if (model.indexOf("+") >= 0 && model.indexOf("Hydro") >= 0) return 358;
    if (model.indexOf("Hydro") >= 0) return 335;
    if (model.indexOf("Imm") >= 0) return 301;
    if (model.indexOf("Pro") >= 0) return 234;
    if (model.indexOf("+") >= 0) return 216;
    return 200;  // Base S21
  }

  // T21 Series
  if (model.indexOf("T21") >= 0) return 190;

  // S19 Series (2020-2023) - check specific variants first
  if (model.indexOf("S19") >= 0) {
    // XP variants
    if (model.indexOf("XP") >= 0 && model.indexOf("Hyd") >= 0) return 257;
    if (model.indexOf("XP") >= 0) return 140;
    // j XP variant
    if (model.indexOf("j") >= 0 && model.indexOf("XP") >= 0) return 151;
    // Pro+ Hydro
    if (model.indexOf("Pro+") >= 0 && model.indexOf("Hyd") >= 0) return 198;
    if (model.indexOf("Pro") >= 0 && model.indexOf("Hyd") >= 0) return 184;
    // k Pro
    if (model.indexOf("k") >= 0 && model.indexOf("Pro") >= 0) return 120;
    // j Pro
    if (model.indexOf("j") >= 0 && model.indexOf("Pro+") >= 0) return 122;
    if (model.indexOf("j") >= 0 && model.indexOf("Pro") >= 0) return 104;
    // Regular Pro
    if (model.indexOf("Pro") >= 0) return 110;
    // Hydro variants
    if (model.indexOf("Hyd") >= 0) return 158;
    // j variants
    if (model.indexOf("j") >= 0) return 90;
    return 95;  // Base S19
  }

  // T19 Series
  if (model.indexOf("T19") >= 0) {
    if (model.indexOf("Pro") >= 0 && model.indexOf("Hyd") >= 0) return 235;
    if (model.indexOf("Hyd") >= 0) return 158;
    return 84;
  }

  // S17 Series - check specific variants first
  if (model.indexOf("S17") >= 0) {
    if (model.indexOf("+") >= 0) return 73;
    if (model.indexOf("e") >= 0) return 64;
    if (model.indexOf("Pro") >= 0) return 62;
    return 56;
  }

  // T17 Series
  if (model.indexOf("T17") >= 0) {
    if (model.indexOf("+") >= 0) return 64;
    if (model.indexOf("e") >= 0) return 53;
    return 40;
  }

  // S15 Series
  if (model.indexOf("S15") >= 0) return 28;

  // T15 Series
  if (model.indexOf("T15") >= 0) return 23;

  // S11 Series
  if (model.indexOf("S11") >= 0) return 21;  // 20.5 TH/s

  // S9 Series - check specific variants first
  if (model.indexOf("S9") >= 0) {
    if (model.indexOf("SE") >= 0) return 16;
    if (model.indexOf("Hydro") >= 0) return 18;
    if (model.indexOf("k") >= 0) return 14;  // 13.5 TH/s
    if (model.indexOf("j") >= 0) return 15;  // 14.5 TH/s
    if (model.indexOf("i") >= 0) return 14;
    return 14;  // Base S9
  }

  // T9 Series
  if (model.indexOf("T9") >= 0) {
    if (model.indexOf("+") >= 0) return 11;  // 10.5 TH/s
    return 13;  // 12.5 TH/s
  }

  // Legacy S-series (pre-S9)
  if (model.indexOf("S7") >= 0) return 5;   // 4.73 TH/s
  if (model.indexOf("S5") >= 0) return 1;   // 1.16 TH/s
  if (model.indexOf("S4") >= 0) return 2;
  if (model.indexOf("S3") >= 0) return 0;   // 440 GH/s
  if (model.indexOf("S2") >= 0) return 1;
  if (model.indexOf("S1") >= 0) return 0;   // 180 GH/s

  // ===== SCRYPT MINERS - Litecoin/Dogecoin (L Series) =====
  // Returns GH/s value (display will show "GH")
  if (model.indexOf("L9") >= 0) return 17;   // 17 GH/s
  if (model.indexOf("L7") >= 0) return 10;   // 9.5 GH/s
  if (model.indexOf("L3+") >= 0) return 1;   // 504-600 MH/s
  if (model.indexOf("L3") >= 0) return 1;    // ~500 MH/s

  // ===== ETHASH MINERS - Ethereum Classic (E Series) =====
  // Returns GH/s value
  if (model.indexOf("E11") >= 0) return 10;  // 9.5 GH/s
  if (model.indexOf("E9") >= 0) {
    if (model.indexOf("Pro") >= 0) return 4; // 3.68 GH/s
    return 3;  // 2.4-3 GH/s
  }
  if (model.indexOf("E7") >= 0) return 1;    // 800 MH/s
  if (model.indexOf("E3") >= 0) return 0;    // 190 MH/s

  // ===== EQUIHASH MINERS - Zcash/Horizen (Z Series) =====
  // Returns kSol/s value
  if (model.indexOf("Z15") >= 0) {
    if (model.indexOf("Pro") >= 0) return 840;
    return 420;
  }
  if (model.indexOf("Z11") >= 0) return 135;
  if (model.indexOf("Z9") >= 0) {
    if (model.indexOf("Mini") >= 0) return 10;
    return 42;
  }

  // ===== X11 MINERS - Dash (D Series) =====
  // Returns GH/s value (D9/D7) or actual for D3
  if (model.indexOf("D9") >= 0) return 1770; // 1770 GH/s = 1.77 TH/s
  if (model.indexOf("D7") >= 0) return 1286; // 1286 GH/s = 1.29 TH/s
  if (model.indexOf("D3") >= 0) return 19;   // 19.3 GH/s

  // ===== KASPA MINERS - KHeavyHash (KS Series) =====
  // Returns TH/s value
  if (model.indexOf("KS5") >= 0) {
    if (model.indexOf("Pro") >= 0) return 21;
    return 20;
  }
  if (model.indexOf("KS3") >= 0) return 9;   // 8.3-9.4 TH/s

  // ===== KADENA MINERS - Blake2S (KA Series) =====
  // Returns TH/s value
  if (model.indexOf("KA3") >= 0) return 166;

  // ===== NERVOS CKB MINERS - Eaglesong (K Series) =====
  // Returns TH/s value
  if (model.indexOf("K7") >= 0) return 64;   // 63.5 TH/s
  if (model.indexOf("K5") >= 0) return 1;    // 1.13 TH/s

  // ===== HANDSHAKE MINERS - Blake2B+SHA3 (HS Series) =====
  // Returns TH/s value
  if (model.indexOf("HS3") >= 0) return 9;

  // ===== DECRED MINERS - Blake256R14 (DR Series) =====
  // Returns TH/s value
  if (model.indexOf("DR5") >= 0) return 35;

  // ===== SIACOIN MINERS - Blake2b (A Series) =====
  // Returns GH/s value
  if (model.indexOf("A3") >= 0) return 815;  // 815 GH/s

  // ===== CRYPTONIGHT MINERS (X3) =====
  // Returns kH/s value
  if (model.indexOf("X3") >= 0) return 220;  // 220 kH/s

  // ===== RANDOMX MINERS - Monero (X5) =====
  // Returns kH/s value
  if (model.indexOf("X5") >= 0) return 212;  // 212 kH/s

  return 0;  // Unknown model
}

// Shorten model name by removing "Antminer " prefix
String shortenModel(const String& model) {
  if (model.startsWith("Antminer ")) {
    return model.substring(9);
  }
  return model;
}

// Get the appropriate hashrate unit for the miner model
String getHashrateUnit(const String& model) {
  // Equihash miners (Z series) - kSol/s
  if (model.indexOf("Z15") >= 0 || model.indexOf("Z11") >= 0 || model.indexOf("Z9") >= 0) {
    return "kS";  // kSol/s
  }

  // CryptoNight/RandomX miners (X3, X5) - kH/s
  if (model.indexOf("X3") >= 0 || model.indexOf("X5") >= 0) {
    return "kH";  // kH/s
  }

  // Scrypt miners (L series) - GH/s or MH/s
  if (model.indexOf("L9") >= 0 || model.indexOf("L7") >= 0) {
    return "GH";  // GH/s for L7, L9
  }
  if (model.indexOf("L3") >= 0) {
    return "MH";  // MH/s for L3
  }

  // Ethash miners (E series) - GH/s or MH/s
  if (model.indexOf("E11") >= 0 || model.indexOf("E9") >= 0) {
    return "GH";  // GH/s for E9, E11
  }
  if (model.indexOf("E7") >= 0 || model.indexOf("E3") >= 0) {
    return "MH";  // MH/s for E3, E7
  }

  // X11 miners (D series) - GH/s
  if (model.indexOf("D9") >= 0 || model.indexOf("D7") >= 0 || model.indexOf("D3") >= 0) {
    return "GH";  // GH/s
  }

  // Siacoin miners (A series) - GH/s
  if (model.indexOf("A3") >= 0) {
    return "GH";
  }

  // Default: TH/s for SHA-256, Kaspa, Kadena, CKB, HNS, Decred miners
  return "T";  // TH/s
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

// Check miner using stock Bitmain firmware API with Digest Authentication
// Returns true if miner found and sets minerModel
bool checkMinerStockAPI(IPAddress ip) {
  char ipStr[16];
  sprintf(ipStr, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
  const char* uri = "/cgi-bin/get_system_info.cgi";

  Serial.println(F("    Trying stock firmware API..."));

  // Step 1: Make initial request to get 401 and nonce
  if (!client.connect(ip, HTTP_PORT)) {
    Serial.println(F("    Stock: Connection failed"));
    return false;
  }

  client.print(F("GET "));
  client.print(uri);
  client.println(F(" HTTP/1.1"));
  client.print(F("Host: "));
  client.println(ipStr);
  client.println(F("Connection: keep-alive"));
  client.println();

  // Wait for response
  unsigned long timeout = millis();
  while (client.available() == 0) {
    if (millis() - timeout > HTTP_TIMEOUT) {
      client.stop();
      Serial.println(F("    Stock: Timeout on challenge"));
      return false;
    }
  }

  // Read headers and look for WWW-Authenticate
  String authHeader = "";
  bool got401 = false;
  while (client.available()) {
    String line = client.readStringUntil('\n');
    if (line.startsWith("HTTP/1.") && line.indexOf("401") > 0) {
      got401 = true;
    }
    if (line.startsWith("WWW-Authenticate:")) {
      authHeader = line.substring(18);  // Skip "WWW-Authenticate: "
      authHeader.trim();
    }
    if (line == "\r" || line.length() == 0) {
      break;  // End of headers
    }
  }

  // Drain any remaining data
  while (client.available()) {
    client.read();
  }

  if (!got401 || authHeader.length() == 0) {
    client.stop();
    Serial.println(F("    Stock: Not 401 or no auth header"));
    return false;
  }

  // Extract nonce from WWW-Authenticate header
  char nonce[64];
  if (!extractNonce(authHeader, nonce, sizeof(nonce))) {
    client.stop();
    Serial.println(F("    Stock: Failed to extract nonce"));
    return false;
  }

  Serial.print(F("    Stock: Got nonce: "));
  Serial.println(nonce);

  // Step 2: Calculate Digest response and make authenticated request
  const char* nc = "00000001";
  const char* cnonce = "arduino1";
  const char* qop = "auth";

  String response = calculateDigestResponse(
    STOCK_USERNAME, STOCK_REALM, STOCK_PASSWORD,
    nonce, nc, cnonce, qop, "GET", uri
  );

  String authHeaderValue = buildDigestAuthHeader(
    STOCK_USERNAME, STOCK_REALM, nonce, uri, response.c_str(), nc, cnonce, qop
  );

  // Make authenticated request
  client.print(F("GET "));
  client.print(uri);
  client.println(F(" HTTP/1.1"));
  client.print(F("Host: "));
  client.println(ipStr);
  client.print(F("Authorization: "));
  client.println(authHeaderValue);
  client.println(F("Accept: application/json"));
  client.println(F("Connection: close"));
  client.println();

  // Wait for response
  timeout = millis();
  while (client.available() == 0) {
    if (millis() - timeout > HTTP_TIMEOUT) {
      client.stop();
      Serial.println(F("    Stock: Timeout on auth request"));
      return false;
    }
  }

  // Check for 200 OK and skip headers
  bool got200 = false;
  while (client.available()) {
    String line = client.readStringUntil('\n');
    if (line.startsWith("HTTP/1.") && line.indexOf("200") > 0) {
      got200 = true;
    }
    if (line == "\r" || line.length() == 0) {
      break;  // End of headers
    }
  }

  if (!got200) {
    client.stop();
    Serial.println(F("    Stock: Auth failed (not 200)"));
    return false;
  }

  // Parse JSON response
  if (client.available()) {
    StaticJsonDocument<512> doc;
    DeserializationError error = deserializeJson(doc, client);
    client.stop();

    if (!error && doc.containsKey("minertype")) {
      minerModel = doc["minertype"].as<String>();
      minerIP = ip;
      Serial.print(F("    Stock: FOUND: "));
      Serial.println(minerModel);
      return true;
    } else {
      Serial.println(F("    Stock: JSON parse failed or no minertype"));
    }
  }

  client.stop();
  return false;
}

// Check miner using vnish API (no authentication required)
bool checkMinerVnishAPI(IPAddress ip) {
  char ipStr[16];
  sprintf(ipStr, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);

  Serial.println(F("    Trying vnish API..."));

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
        Serial.println(F("    Vnish: Timeout"));
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
        Serial.print(F("    Vnish: FOUND: "));
        Serial.println(minerModel);
        return true;
      } else {
        Serial.println(F("    Vnish: JSON parse failed or no miner field"));
      }
    }
    client.stop();
  } else {
    Serial.println(F("    Vnish: Connection failed"));
  }
  return false;
}

// Main check function - tries vnish first, then stock firmware
bool checkMinerAtIP(IPAddress ip) {
  char ipStr[16];
  sprintf(ipStr, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);

  Serial.print(F("  Checking "));
  Serial.println(ipStr);

  // Try vnish API first (most common custom firmware)
  if (checkMinerVnishAPI(ip)) {
    return true;
  }

  // Small delay before trying stock API
  delay(500);

  // Try stock Bitmain firmware API
  if (checkMinerStockAPI(ip)) {
    return true;
  }

  Serial.println(F("    No miner found at this IP"));
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

  // Build display string: shortened model + hashrate with correct unit
  String shortName = shortenModel(minerModel);
  int hashrate = getTerahash(minerModel);
  String unit = getHashrateUnit(minerModel);
  String displayStr;
  if (hashrate > 0) {
    displayStr = shortName + " " + String(hashrate) + unit;
  } else {
    displayStr = shortName;  // Unknown model, just show name
  }

  lcd.clear();
  lcd.setCursor(0, 0);
  if (displayStr.length() > 16) {
    lcd.print(displayStr.substring(0, 16));
  } else {
    lcd.print(displayStr);
  }

  lcd.setCursor(0, 1);
  lcd.print(ipStr);

  Serial.println(F("\n=== MINER INFO ==="));
  Serial.print(F("Model: "));
  Serial.println(minerModel);
  Serial.print(F("Hashrate: "));
  Serial.print(hashrate);
  Serial.print(F(" "));
  Serial.println(unit);
  Serial.print(F("Display: "));
  Serial.println(displayStr);
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

  lcd.init();
  lcd.backlight();
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
