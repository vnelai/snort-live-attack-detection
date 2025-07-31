# Task 1: SSH Brute-Force Attack Detection

## 🎯 Goal  
Detect and block an SSH brute-force attack using Snort in IPS mode.

---

## 🧪 Environment Setup  
- Checked interfaces using `ifconfig`
- Confirmed active interface: `eth0`

---

## 📦 Sniffing the Traffic
Used Snort in sniffer mode to capture deep packet data:
`sudo snort -i eth0 -X -l .`  
→ Let it run, then stopped with `Ctrl + C`

Result: `snort.log.xxxxxxx` file created for analysis

---

## 📊 Port Usage Analysis
Ran the following to identify heavily targeted ports:
`sudo snort -r snort.log.xxxxxxx -X | grep "->" | awk -F'->' '{print $2}' | awk -F':' '{print $2}' | sort | uniq -c | sort -nr`

Top hit: **Port 22 (SSH)**

---

## 📍 Source IP Extraction
Filtered by port 22 to find attacker IPs:
`sudo snort -r snort.log.xxxxxxx -v | grep ':22' | awk -F'->' '{print $1}' | awk -F' ' '{print $2}' | awk -F':' '{print $1}' | sort | uniq -c | sort -nr`

Identified attacker IP: `10.10.245.36`  
Target IP: `10.10.140.29`

---

## ✍️ Snort Rule
Dropped repeated SSH attempts:
`drop tcp any any -> any 22 (msg:"SSH attack"; sid:100001; rev:1;)`

Saved in: `/etc/snort/rules/local.rules`

---

## 🚀 IPS Mode
Executed Snort in IPS mode with:
`sudo snort -c /etc/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A full`

After about a minute, the desktop revealed the flag.

---

## 🏁 Result

- **Flag:** `THM{81b7fef657f8aaa6e4e200d616738254}`
- **Service under attack:** SSH  
- **Protocol/Port:** TCP/22
