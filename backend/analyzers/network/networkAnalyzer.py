import pyshark
import json
import datetime


def extract_cipher_suite_info(pcap_file_path, output_json_path):
    """
    Extract cipher suite IDs and general packet information from PCAP file.

    Args:
        pcap_file_path (str): Path to the PCAP file
        output_json_path (str): Path to output JSON file
    """
    cap = pyshark.FileCapture(pcap_file_path)
    packet_data = []

    print(f"Processing packets from {pcap_file_path}...")

    for i, packet in enumerate(cap):
        packet_info = {
            'packet_number': i + 1,
            'timestamp': str(packet.sniff_time) if hasattr(packet, 'sniff_time') else None,
            'length': int(packet.length) if hasattr(packet, 'length') else None,
            'layers': [layer.layer_name for layer in packet.layers],
            'cipher_suite_id': None,
            'cipher_suite_name': None,
            'tls_version': None,
            'server_name': None,
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'protocol': None
        }

        if hasattr(packet, 'ip'):
            packet_info['src_ip'] = packet.ip.src
            packet_info['dst_ip'] = packet.ip.dst
            packet_info['protocol'] = packet.ip.proto

        if hasattr(packet, 'tcp'):
            packet_info['src_port'] = int(packet.tcp.srcport)
            packet_info['dst_port'] = int(packet.tcp.dstport)
        elif hasattr(packet, 'udp'):
            packet_info['src_port'] = int(packet.udp.srcport)
            packet_info['dst_port'] = int(packet.udp.dstport)

        if hasattr(packet, 'tls'):
            try:
                if hasattr(packet.tls, 'record_version'):
                    packet_info['tls_version'] = packet.tls.record_version

                if hasattr(packet.tls, 'handshake_extensions_server_name'):
                    packet_info['server_name'] = packet.tls.handshake_extensions_server_name

                if hasattr(packet.tls, 'handshake_ciphersuite'):
                    packet_info['cipher_suite_id'] = packet.tls.handshake_ciphersuite

                if hasattr(packet.tls, 'handshake_ciphersuite_str'):
                    packet_info['cipher_suite_name'] = packet.tls.handshake_ciphersuite_str

                # Alternative fields for cipher suites
                if not packet_info['cipher_suite_id']:
                    for field in packet.tls._all_fields:
                        if 'cipher' in field.name.lower() and 'suite' in field.name.lower():
                            packet_info['cipher_suite_id'] = field.value
                            break

            except AttributeError as e:
                pass

        elif hasattr(packet, 'ssl'):
            try:
                if hasattr(packet.ssl, 'handshake_ciphersuite'):
                    packet_info['cipher_suite_id'] = packet.ssl.handshake_ciphersuite
                if hasattr(packet.ssl, 'record_version'):
                    packet_info['tls_version'] = packet.ssl.record_version
            except AttributeError:
                pass

        packet_data.append(packet_info)

        if (i + 1) % 1000 == 0:
            print(f"Processed {i + 1} packets...")

    cap.close()

    with open(output_json_path, 'w') as f:
        json.dump(packet_data, f, indent=2, default=str)

    print(f"Extracted data from {len(packet_data)} packets")
    print(f"Results saved to {output_json_path}")

    tls_packets = sum(1 for p in packet_data if p['cipher_suite_id'] is not None)
    unique_cipher_suites = len(set(p['cipher_suite_id'] for p in packet_data if p['cipher_suite_id'] is not None))

    print(f"TLS/SSL packets with cipher suite info: {tls_packets}")
    print(f"Unique cipher suites found: {unique_cipher_suites}")

    return packet_data


if __name__ == "__main__":
    pcap_file = './data/pcap/anonymized-2021-08-06.pcap'
    output_file = './cipher_suite_analysis.json'

    extract_cipher_suite_info(pcap_file, output_file)
