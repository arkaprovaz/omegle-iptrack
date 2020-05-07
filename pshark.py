import pyshark
from geolite2 import geolite2
import socket, subprocess 
import time

cap = pyshark.LiveCapture(interface='6')
my_ip = socket.gethostbyname(socket.gethostname())
reader = geolite2.reader()

def get_ip_location(ip):
    location = reader.get(ip)
    
    try:
        country = location["country"]["names"]["en"]
    except:
        country = "Unknown"

    try:
        subdivision = location["subdivisions"][0]["names"]["en"]
    except:
        subdivision = "Unknown"    

    try:
        city = location["city"]["names"]["en"]
    except:
        city = "Unknown"

    try:
        postal = location["postal"]["code"]
    except:
        postal = "Unknown"
    
    return city, subdivision, country, postal 
prev_ip = ""
for packet in cap.sniff_continuously():
    #print(packet.ip.src, "    " , packet.ip.dst)
    
    ip = packet.ip.src if packet.ip.src != my_ip else packet.ip.dst
    #print(ip)
    #print(reader.get(ip))
    if prev_ip!= ip:
        try:
            city, sub, country, postal = get_ip_location(ip)
            print(">>> " + city + ", " + sub + ", " + country + ", " + postal + " \n IP: " + ip)
        except:
            try:
                real_ip = socket.gethostbyname(ip)
                city, sub, country, postal = get_ip_location(real_ip)
                print(">>> " + city + ", " + sub + ", " + country + ", " + postal + " \n IP: " + real_ip)
            except:
                print("Not found")
        prev_ip=ip

    #time.sleep(0.1)
