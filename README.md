# Antminer Discovery - Arduino Mega 2560 Version

## Hardware Requirements

- **Arduino Mega 2560** (8KB RAM)
- **W5100 Ethernet Shield**
- **16x2 LCD Display** (parallel connection)
- **Ethernet cable** (direct to Antminer)

## Pin Configuration

### Ethernet Shield (W5100)
- Uses SPI bus on Mega: Pins 50-53 (MISO, MOSI, SCK, SS)
- **Note**: W5100 shield sits on top of Mega, same as Uno

### LCD Display
- RS: Pin 9
- EN: Pin 8
- D4: Pin 7
- D5: Pin 6
- D6: Pin 5
- D7: Pin 3
- VSS: GND
- VDD: 5V
- V0: Potentiometer for contrast
- RW: GND
- A: 5V (with 220Ω resistor)
- K: GND

## Network Configuration

```
Arduino Mega: 192.168.1.1
Antminer:     192.168.1.100 (assigned via DHCP)
Subnet:       255.255.255.0
```

## What This Does

1. **Starts DHCP server** on Arduino to assign IP to Antminer
2. **Waits 30 seconds** for Antminer to request IP via DHCP
3. **Scans network** to find the Antminer:
   - Checks 192.168.1.100 (assigned DHCP IP)
   - Tries fallback IPs (101, 102)
   - Scans subnet if needed
4. **Queries vnish-api** at `/api/v1/info` endpoint
5. **Displays** miner model and IP on LCD
6. **Monitors connection** every 10 seconds
7. **Auto-reconnects** when Antminer disconnects or reconnects

## Expected Serial Output

```
================================
  Antminer Discovery v2.0
  Arduino Mega 2560
================================
Free RAM: 7200 bytes

=== Network Initialization ===
Arduino IP: 192.168.1.1
DHCP server started on port 67
[LCD] DHCP Server | Ready

=== DHCP Wait (30s) ===
Waiting for Antminer to request IP...

[DHCP] Packet received (300 bytes)
  -> DHCP DISCOVER
  -> Sent DHCP OFFER (IP: 192.168.1.100)

[DHCP] Packet received (310 bytes)
  -> DHCP REQUEST
  -> Sent DHCP ACK (IP: 192.168.1.100)

DHCP wait complete

=== Miner Discovery ===
Checking DHCP IP: 192.168.1.100...
  -> FOUND: Antminer S19

=== MINER INFO ===
Model: Antminer S19
IP: 192.168.1.100
==================

Free RAM at end: 6800 bytes
Setup complete
```

## LCD Display Output

**During DHCP:**
```
Line 1: DHCP: Antminer
Line 2: Requesting IP...
```

**When Found:**
```
Line 1: Antminer S19
Line 2: 192.168.1.100
```

**When Disconnected:**
```
Line 1: Connection
Line 2: Lost!
```

**Waiting for Reconnection:**
```
Line 1: Waiting for
Line 2: new connection
```

## Auto-Reconnect Feature

The Arduino continuously monitors the Antminer connection:

**How it works:**
1. **Every 10 seconds**: Sends HTTP HEAD request to check if miner responds
2. **On failure**: Increments failure counter
3. **After 3 consecutive failures**: Declares connection lost
4. **Automatically**: Waits for new DHCP request and rediscovers miner
5. **Displays**: Status updates on LCD throughout

**Serial output during monitoring:**
```
[Monitor] Checking connection... OK
[Monitor] Checking connection... OK
[Monitor] Checking connection... FAILED (1/3)
[Monitor] Checking connection... FAILED (2/3)
[Monitor] Checking connection... FAILED (3/3)

!!! CONNECTION LOST !!!
Resetting... waiting for new connection

=== Waiting for New Connection ===
DHCP wait (30s)...
[DHCP] Packet received...
  -> DHCP DISCOVER
  -> Sent DHCP OFFER
[DHCP] Packet received...
  -> DHCP REQUEST
  -> Sent DHCP ACK

Attempting discovery...
Checking DHCP IP: 192.168.1.100...
  -> FOUND: Antminer S19

[Monitor] Checking connection... OK
```

**Use Cases:**
- ✅ Unplug Ethernet cable → Auto-reconnects when plugged back
- ✅ Power cycle Antminer → Detects and reconnects automatically
- ✅ Network glitch → Recovers after 3 failed checks
- ✅ Swap to different Antminer → Discovers new one automatically

## Memory Usage (Mega vs Uno)

| Component | Size | % of Mega (8KB) | % of Uno (2KB) |
|-----------|------|-----------------|----------------|
| DHCP Buffer | 548 bytes | 6.8% | 27% |
| LCD Overhead | 200 bytes | 2.5% | 10% |
| Ethernet | 400 bytes | 5.0% | 20% |
| JSON Document | 256 bytes | 3.2% | 12.8% |
| Stack + Other | 500 bytes | 6.2% | 25% |
| **Total** | ~2KB | **~24%** | **~95%** ✗ |

**Mega has plenty of headroom!**

## Differences from Uno Version

### Added Back:
✅ LCD display (removed from Uno due to memory)
✅ Moderate debugging messages
✅ Memory monitoring (`getFreeRAM()`)
✅ Better formatted serial output
✅ Section headers in serial output

### Kept:
✅ Custom DHCP server implementation
✅ Global dhcpBuffer (no stack overflow)
✅ Antminer discovery logic
✅ vnish-api query

## Testing Checklist

When you upload to Mega and connect Antminer:

1. **Check Serial Monitor (115200 baud)**:
   - [ ] Sees "DHCP server started"
   - [ ] Receives DHCP DISCOVER packet
   - [ ] Sends DHCP OFFER
   - [ ] Receives DHCP REQUEST
   - [ ] Sends DHCP ACK
   - [ ] Finds miner at 192.168.1.100
   - [ ] Displays miner model

2. **Check LCD Display**:
   - [ ] Shows startup message
   - [ ] Shows "DHCP Server Ready"
   - [ ] Shows "DHCP: Antminer Requesting IP..."
   - [ ] Shows miner model and IP

3. **If DHCP Fails**:
   - Check serial output for packet reception
   - Verify Antminer is powered on
   - Check Ethernet cable connection
   - Verify W5100 shield is seated properly

## Troubleshooting

### "No DHCP packets received"
- Antminer may not be requesting DHCP
- Check Ethernet cable
- Try power cycling the Antminer
- Verify Antminer is set to DHCP mode (not static IP)

### "DHCP packets received but miner not found"
- DHCP handshake may have failed
- Antminer might not have accepted the IP
- Try pinging 192.168.1.100 from another device
- Check serial output for error messages

### "Miner found but model is empty"
- vnish-api query failed
- Check `/api/v1/info` endpoint on Antminer
- Verify Antminer is running vnish firmware

## Next Steps if DHCP Doesn't Work

If the DHCP server doesn't work with the Antminer:

1. **Capture packets**: Use Wireshark to see what the Antminer is sending
2. **Compare with dnsmasq**: Compare our packets vs Linux dnsmasq
3. **Debug packet format**: Check BOOTP/DHCP options
4. **Try different options**: Adjust lease time, options order, etc.
5. **Consider alternatives**: Static IP on Antminer, or use real router

## Advantages of This Approach

✅ Direct Arduino ↔ Antminer connection (no router)
✅ Custom DHCP server (learning experience)
✅ Displays results on LCD
✅ Portable system
✅ Arduino Mega has enough RAM to be reliable

## Files

- `ethernet-hash-mega.ino` - Main sketch for Arduino Mega
- `README.md` - This file

## Upload Instructions

1. Open `ethernet-hash-mega.ino` in Arduino IDE
2. Select **Board**: Arduino Mega 2560
3. Select correct **Port**
4. Click **Upload**
5. Open **Serial Monitor** at 115200 baud
6. Connect Ethernet cable to Antminer
7. Watch serial output and LCD

Good luck! 🚀
# arduino-antminer-model-detect
