# 🛠️ Snort CLI Cheatsheet & Analysis Toolkit

A collection of my favorite commands and parsing tricks for using Snort effectively during hands-on investigations and blue team labs.

---

## 🐍 Snort Modes

### Sniffer Mode (Live Packet Capture)  
`sudo snort -i eth0 -X -l .`  
- `-i eth0`: specify interface  
- `-X`: deep packet inspection  
- `-l .`: log to current directory

### Read from PCAP or Log  
`sudo snort -r snort.log.xxxxxxx -X`

---

## 🔍 Log Parsing Tricks

### Analyze Top Destination Ports  
`sudo snort -r snort.log.xxxxxxx -X | grep "->" | awk -F'->' '{print $2}' | awk -F':' '{print $2}' | sort | uniq -c | sort -nr`  
- Reveals most used destination ports  
- Helps spot brute-force targets or shell backdoors

### Extract Top Source IPs to a Port (e.g., 22)  
`sudo snort -r snort.log.xxxxxxx -v | grep ':22' | awk -F'->' '{print $1}' | awk -F' ' '{print $2}' | awk -F':' '{print $1}' | sort | uniq -c | sort -nr`  
- Shows which IPs hit port 22 most  
- Useful for brute-force or scan detection

---

## 📜 Writing Snort Rules

### Drop SSH Brute-Force Attempts  
`drop tcp any any -> any 22 (msg:"SSH attack"; sid:100001; rev:1;)`

### Alert on Reverse Shell to Port 4444  
`alert tcp any any -> any 4444 (msg:"Test rule"; sid:999999; rev:1;)`

---

## 🚀 IPS Mode Execution

Run Snort with IPS mode (afpacket):  
`sudo snort -c /etc/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A full`

- `-Q`: IPS mode  
- `--daq afpacket`: inline packet processing  
- `-A full`: logs alerts with details  
- Use `eth0:eth1` if needed (depends on config)

---

## 🧪 Bonus: Check If Log is Binary  
`head snort.log.xxxxxxx`  
- If it’s gibberish → binary log  
- Use `tcpdump` to read

---

## 🐚 Tcpdump Reverse Shell Check  
`sudo tcpdump -nnr snort.log.xxxxxxx | grep -E '4444|34770|80'`  
- Look for back-and-forth activity on suspicious ports

---

## 💡 Tips

- Always analyze both **inbound and outbound** traffic  
- Use **sorted counts** to quickly find anomalies  
- Snort rules are powerful — even simple ones go a long way  
- Be patient — Snort sometimes takes 30–60 seconds to trigger the flag

---


