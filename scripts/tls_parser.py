import pyshark
import os
import csv 


interface = 'eth0'  # or 'wlan0' depending on your system
csv_path = 'tls_metadata.csv'





tls_packets = pyshark.LiveCapture(interface=interface, display_filter='tls')


with open(csv_path, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['TLS_Version', 'Handshake_Type', 'Cipher_Suite', 'SNI'])

    try:
        for pkt in tls_packets:
            if hasattr(pkt, 'tls'):
                version = getattr(pkt.tls, 'record_version', 'N/A')
                handshake_type = getattr(pkt.tls, 'handshake_type', 'N/A')
                cipher_suite = getattr(pkt.tls, 'handshake_ciphersuite', 'N/A')
                sni = getattr(pkt.tls, 'handshake_extensions_server_name', 'N/A')

                print(f'TLS record_version: {version} | Handshake: {handshake_type} | Cipher: {cipher_suite} | SNI: {sni}')
                writer.writerow([version, handshake_type, cipher_suite, sni])
            else:
                print("Not a TLS packet")
    finally:
        tls_packets.close()

