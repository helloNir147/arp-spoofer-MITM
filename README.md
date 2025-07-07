# ARP Spoofer + MITM עם Packet Sniffing

פרויקט זה הוא כלי ללמידה המשלב ARP Spoofing יחד עם Man-in-the-Middle (MITM) בסיסי,  
הכלי מתחזה לראוטר מול מחשב קורבן ולהפך, ותופס את התעבורה בין השניים.

---

## דרישות מוקדמות

- מערכת הפעלה לינוקס (Ubuntu/Debian מומלץ)
- Python 3
- הרשאות מנהל (root / sudo)
- ספריית Scapy מותקנת

---

## התקנת סביבת העבודה

```bash
sudo apt update
sudo apt install python3 python3-pip
sudo pip3 install scapy
