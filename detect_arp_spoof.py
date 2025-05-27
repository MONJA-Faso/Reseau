from scapy.all import ARP, sniff, conf
from collections import defaultdict
import time

# Dictionnaire IP → ensemble de MACs
ip_mac_table = defaultdict(set)

# Fichier log
log_file_path = "arp_alerts.log"

def log_alert(message):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    full_message = f"[{timestamp}] {message}"
    print(full_message)

    with open(log_file_path, "a") as f:
        f.write(full_message + "\n")

def process_packet(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP Reply
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        ip_mac_table[ip].add(mac)

        if len(ip_mac_table[ip]) > 1:
            log_alert(f"[!!] POSSIBLE ARP SPOOFING DÉTECTÉ : {ip} est associé à plusieurs MAC : {ip_mac_table[ip]}")

def main():
    # Détection automatique de l’interface réseau par défaut
    interface = conf.iface
    print(f"🔍 Surveillance ARP en cours sur l'interface : {interface} (CTRL+C pour quitter)")

    try:
        sniff(store=False, prn=process_packet, filter="arp", iface=interface)
    except PermissionError:
        print("❌ Permission refusée. Lance le script avec sudo.")
    except KeyboardInterrupt:
        print("\n🛑 Arrêt manuel. Surveillance terminée.")
    except Exception as e:
        print(f"❌ Erreur : {e}")

if __name__ == "__main__":
    main()



## sudo -E venv-arp/bin/python detect_arp_spoof.py   ## pour lancer lescript dans cette environnement virtuel et avec privilège du root