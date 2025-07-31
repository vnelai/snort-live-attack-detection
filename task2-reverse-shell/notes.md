# Task 2: Reverse Shell Detection (Outbound)

## 🎯 Goal  
Detect and stop an outbound reverse shell attempt using Snort.

---

## 🧪 Environment Prep  
- Closed the VM from Task 1  
- Launched new VM for Task 2  
- Confirmed active interface: `eth0` via `ifconfig`

---

## 📦 Sniffing the Traffic  
Used Snort in sniffer mode:  
`sudo snort -i eth0 -X -l .`  
→ Waited 1–2 minutes and stopped with `Ctrl + C`  
→ Generated `snort.log.xxxxxxx` file

---

## 📊 Port Usage Check  
Sorted destination ports to find suspicious outbound connections:  
`sudo snort -r snort.log.xxxxxxx -X | grep "->" | awk -F'->' '{print $2}' | awk -F':' '{print $2}' | sort | uniq -c | sort -nr`

Findings:  
- Port **4444** was highly active (common for reverse shells)  
- Port 80 and 34770 also appeared, but 4444 stood out

---

## 🧪 tcpdump Verification  
Verified outbound shell behavior with:  
`sudo tcpdump -nnr snort.log.xxxxxxx | grep -E '4444|34770|80'`

Confirmed repeated traffic to port 4444 — likely reverse shell back to attacker.

---

## ✍️ Snort Rule  
Blocked reverse shell attempt using:  
`alert tcp any any -> any 4444 (msg:"Test rule"; sid:999999; rev:1;)`  
→ Saved in `/etc/snort/rules/local.rules`

---

## 🚀 IPS Mode  
Launched Snort in IPS mode:  
`sudo snort -c /etc/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A full`

→ Let it run ~1 min.  
→ Checked alert logs… and flag appeared on Desktop 🎯

---

## 🏁 Result

- **Flag:** `THM{0ead8c494861079b1b74ec2380d2cd24}`
- **Protocol/Port:** TCP/4444  
- **Associated Tool:** Metasploit
