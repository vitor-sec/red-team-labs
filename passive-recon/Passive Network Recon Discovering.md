# Passive Network Reconnaissance: Discovering a DLNA MediaServer via SSDP Traffic Analysis

> Demonstrating how broadcast and multicast traffic on a LAN can be leveraged for host enumeration and software fingerprinting **without sending a single packet to the target** — and how a SOC would detect and contain this activity.

## TL;DR

By passively capturing 60 seconds of LAN traffic with `tshark`, I identified an unknown host (`192.168.15.2`) as a UPnP/DLNA MediaServer, extracted its OS kernel version, its DLNA library, and an internal HTTP description endpoint — all without active scanning. The lab also correlates packet captures with `ss` output to map traffic back to local processes (`packet ↔ process`), and concludes with a Sigma detection rule for unauthorized SSDP advertisements crossing trust boundaries.

## Why This Matters

Active scanning (`nmap -sV`) is loud — it generates connection attempts that appear in firewall logs and trigger IDS signatures. Passive recon relies on traffic the targets emit voluntarily. For SOC analysts, understanding what an attacker can learn *without touching the wire* defines the baseline of "normal LAN noise" that must be tuned out — and the anomalies that must not be.

## Lab Environment

| Component | Detail |
|-----------|--------|
| Sensor host | Kali Linux, dual-homed (`eth0`, `wlan0`) |
| Subnet | `192.168.15.0/24` |
| Capture tools | `tshark`, `tcpdump` |
| Correlation tools | `ss`, `arp` |
| Target | Unknown host at `192.168.15.2` (initially unidentified) |

## Methodology

### 1. Interface Selection vs Route Selection

A frequent source of confusion: **`tshark` captures whatever crosses the chosen interface, regardless of the routing table.** The route `metric` only governs which interface the *host itself* uses to send outbound traffic.

This distinction is operationally important:
- Capturing on `wlan0` showed encrypted egress traffic (TLS/443, QUIC/UDP 443) to Google, Cloudflare, GitHub IP ranges — the host's actual internet activity.
- Capturing on `eth0` showed almost no internet traffic but a rich stream of LAN broadcasts/multicasts: ARP, IGMP, mDNS, SSDP.

The interesting reconnaissance signal lives on the LAN-facing interface, not on the high-throughput egress interface.

### 2. Baseline LAN Traffic Categorization

Running on `eth0` for 60 seconds produced four traffic classes:

| Protocol | Destination | Purpose |
|----------|-------------|---------|
| ARP | broadcast | Layer-2 address resolution and gateway liveness checks |
| IGMP | `224.0.0.1` | Multicast group membership management |
| mDNS | `224.0.0.251:5353` | Local service discovery (Bonjour/Avahi) |
| SSDP | `239.255.255.250:1900` | UPnP device announcements |

Of these, **SSDP is the most informative for passive enumeration** because devices voluntarily advertise their identity, software stack, and service endpoints.

### 3. The Discovery: SSDP NOTIFY from `192.168.15.2`

Filtering the capture to SSDP only:

```bash
sudo tshark -i eth0 -Y "udp.port==1900"
```

A `NOTIFY` packet from `192.168.15.2` to `239.255.255.250` carried these headers:

```
NOTIFY * HTTP/1.1
Host: 239.255.255.250:1900
Server: DLNADOC/1.50 Linux/3.10.104 UPnP/1.0 RKDLNALib/2.0
Location: http://192.168.15.2:38389/deviceDescription/MediaServer
NT: urn:schemas-upnp-org:device:MediaServer:1
NTS: ssdp:alive
```

**What I learned from one unsolicited packet:**

| Intelligence | Value | How it would be used |
|-------------|-------|---------------------|
| Host identity | `192.168.15.2` is a MediaServer | Target classification |
| Kernel | Linux 3.10.104 | Public CVE search against this kernel branch |
| DLNA stack | `RKDLNALib/2.0` (Rockchip vendor) | Hardware fingerprint — likely TV box / set-top / IoT |
| Exposed endpoint | `http://192.168.15.2:38389/deviceDescription/MediaServer` | Targeted follow-up without port scanning |
| Service types | `MediaServer:1`, `ConnectionManager:1`, `ContentDirectory:1` | Application-layer attack surface |

The `Time to Live` on the IP packet was `4` — a deliberately low TTL ensuring the announcement stays within the local broadcast domain. This is by design, not misconfiguration.

### 4. Confirming the Endpoint (Still Passive-Adjacent)

A single targeted `curl` to the advertised URL — not a port scan — confirms the device fully:

```bash
curl -v http://192.168.15.2:38389/deviceDescription/MediaServer
```

This is technically active traffic but is one request to one URL that the device advertised publicly. The footprint is minimal compared to even a stealth Nmap scan.

### 5. Packet ↔ Process Correlation

`tshark` answers *"what is on the wire?"*. `ss` answers *"which local process owns this socket?"*. Together they map network behavior to userspace.

```bash
ss -tunap
```

This revealed which local processes were generating each connection observed in the capture — for example, `firefox-esr` for TLS/443 traffic, and Spotify holding open UDP sockets on `:1900` (SSDP) and `:5353` (mDNS) for its own device discovery features.

**Operational lesson for SOC work:** when a suspicious connection appears in NetFlow or PCAP, `ss -tunap` (Linux) or `Get-NetTCPConnection` + process lookup (Windows) is the immediate next step to attribute the traffic to a process.

## What Encrypted Egress Hides — and What It Doesn't

Modern internet traffic is dominated by TLS and QUIC. Capturing `wlan0` showed plenty of port 443 traffic but no readable content. The recoverable metadata, however, is significant:

| Visible | Hidden |
|---------|--------|
| Destination IPs | Page content |
| Destination ports / protocols | Credentials, messages |
| Connection timing and volume | Specific URLs (usually) |
| TLS SNI (in many cases) | POST bodies |
| DNS queries (if not encrypted) | Response bodies |

The rule of thumb: **on modern networks, metadata is visible, content is encrypted**. Most detection use cases rely on metadata analysis precisely because of this.

## MITRE ATT&CK Mapping

| Technique | ID | Application |
|-----------|-----|-------------|
| Network Sniffing | [T1040](https://attack.mitre.org/techniques/T1040/) | Passive capture with tshark |
| Remote System Discovery | [T1018](https://attack.mitre.org/techniques/T1018/) | Identifying live hosts via broadcast traffic |
| Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | Service identification via SSDP advertisements |
| Gather Victim Host Information: Software | [T1592.002](https://attack.mitre.org/techniques/T1592/002/) | DLNA library / kernel version extraction |

## Defensive Perspective

### Why this traffic is risky on a flat network

UPnP/SSDP was designed for trusted home LANs. In a corporate environment:

1. **Information disclosure** — devices broadcast software versions and endpoints to every host on the segment, including a compromised workstation.
2. **Attack surface** — UPnP services have a long history of CVEs, particularly on embedded Linux stacks like the one observed here (`Linux 3.10.104` is end-of-life and has known unpatched issues).
3. **C2 channel risk** — UPnP IGD can be abused for port mapping if exposed to the WAN side.

### Mitigations

- Place IoT and media devices on a dedicated VLAN with no route to user/server segments
- Block `udp/1900` and `udp/5353` at the L3 boundary between trust zones
- Disable UPnP on corporate routers entirely
- Monitor for SSDP traffic *crossing* VLAN boundaries — by design it should never reach across

### Sigma Detection Rule

A corresponding rule is published in the [`Blue-Team-Labs/detections/`](../../Blue-Team-Labs/detections/) directory of this portfolio.

## Useful tshark Filters from This Lab

```bash
# SSDP only
sudo tshark -i eth0 -Y "udp.port==1900"

# All traffic to/from a specific host
sudo tshark -i eth0 -Y "ip.addr==192.168.15.2"

# QUIC (HTTP/3) traffic
sudo tshark -i wlan0 -Y "udp.port==443"

# TLS traffic
sudo tshark -i wlan0 -Y "tcp.port==443"

# mDNS
sudo tshark -i eth0 -Y "udp.port==5353"
```

## Key Takeaways

- A single unsolicited SSDP packet leaked the OS kernel, vendor library, and an internal HTTP endpoint — equivalent in value to several minutes of active scanning, with zero packets sent to the target
- `tshark` shows *what crossed the wire*; `ss` shows *which process owned the socket* — together they enable end-to-end attribution
- Route `metric` determines egress path but does not affect what a capture sees on a given interface — these are independent concerns
- Discovery protocols designed for home LANs (UPnP, mDNS) are reconnaissance gifts on flat corporate networks

## References

- [UPnP Device Architecture 2.0](https://openconnectivity.org/developer/specifications/upnp-resources/upnp/) — Open Connectivity Foundation
- [RFC 6762](https://datatracker.ietf.org/doc/html/rfc6762) — Multicast DNS
- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [SANS — Passive Network Discovery](https://www.sans.org/reading-room/)
