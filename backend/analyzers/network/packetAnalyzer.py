#!/usr/bin/env python3
"""
Cipher Suite Analysis Tool for PQC Network Discovery
Analyzes packet capture data and decodes TLS cipher suite IDs to their descriptive names.
"""

import json
import argparse
import sys
import subprocess
import re
from collections import Counter
from typing import Dict, List, Optional, Any


class CipherSuiteDatabase:
    def __init__(self):
        self.cipher_suites = {
            # TLS 1.3 Cipher Suites (RFC 8446)
            0x1301: "TLS_AES_128_GCM_SHA256",
            0x1302: "TLS_AES_256_GCM_SHA384", 
            0x1303: "TLS_CHACHA20_POLY1305_SHA256",
            0x1304: "TLS_AES_128_CCM_SHA256",
            0x1305: "TLS_AES_128_CCM_8_SHA256",

            # TLS 1.2 and earlier cipher suites
            0x0001: "TLS_RSA_WITH_NULL_MD5",
            0x0002: "TLS_RSA_WITH_NULL_SHA",
            0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
            0x0004: "TLS_RSA_WITH_RC4_128_MD5",
            0x0005: "TLS_RSA_WITH_RC4_128_SHA",
            0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
            0x0007: "TLS_RSA_WITH_IDEA_CBC_SHA",
            0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
            0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
            0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            0x000B: "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
            0x000C: "TLS_DH_DSS_WITH_DES_CBC_SHA",
            0x000D: "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
            0x000E: "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
            0x000F: "TLS_DH_RSA_WITH_DES_CBC_SHA",
            0x0010: "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
            0x0011: "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
            0x0012: "TLS_DHE_DSS_WITH_DES_CBC_SHA",
            0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
            0x0014: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
            0x0015: "TLS_DHE_RSA_WITH_DES_CBC_SHA",
            0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
            0x0017: "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
            0x0018: "TLS_DH_anon_WITH_RC4_128_MD5",
            0x0019: "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
            0x001A: "TLS_DH_anon_WITH_DES_CBC_SHA",
            0x001B: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",

            # AES Cipher Suites (RFC 3268, RFC 5246)
            0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
            0x0030: "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
            0x0031: "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
            0x0032: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
            0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
            0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA",
            0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
            0x0036: "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
            0x0037: "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
            0x0038: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
            0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
            0x003A: "TLS_DH_anon_WITH_AES_256_CBC_SHA",

            # Additional AES and SHA-256 suites
            0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
            0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
            0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
            0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",

            # GCM Cipher Suites (RFC 5288)
            0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
            0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
            0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",

            # Elliptic Curve Cipher Suites (RFC 4492, RFC 5289)
            0xC002: "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
            0xC003: "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
            0xC004: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
            0xC005: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
            0xC006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
            0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
            0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
            0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
            0xC00B: "TLS_ECDH_RSA_WITH_RC4_128_SHA",
            0xC00C: "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
            0xC00D: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
            0xC00E: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
            0xC00F: "TLS_ECDHE_RSA_WITH_NULL_SHA",
            0xC010: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
            0xC011: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
            0xC012: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            0xC013: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            0xC014: "TLS_ECDH_anon_WITH_NULL_SHA",
            0xC015: "TLS_ECDH_anon_WITH_RC4_128_SHA",
            0xC016: "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
            0xC017: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
            0xC018: "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
            0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
            0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            0xC025: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
            0xC026: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
            0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            0xC029: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
            0xC02A: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
            0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",

            # ChaCha20-Poly1305 Cipher Suites (RFC 7905)
            0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",

            # Post-Quantum Cryptography / Experimental suites
            # These might be experimental or vendor-specific
            0x1A1A: "EXPERIMENTAL_PQC_SUITE_1A1A",
            0x4A4A: "EXPERIMENTAL_PQC_SUITE_4A4A", 
            0x5A5A: "EXPERIMENTAL_PQC_SUITE_5A5A",
            0x8A8A: "EXPERIMENTAL_PQC_SUITE_8A8A",
            0xDADA: "EXPERIMENTAL_PQC_SUITE_DADA",

            # GREASE values (RFC 8701) - Generate Random Extensions And Sustain Extensibility
            0x0A0A: "GREASE_0A0A",
            0x1A1A: "GREASE_1A1A",
            0x2A2A: "GREASE_2A2A", 
            0x3A3A: "GREASE_3A3A",
            0x4A4A: "GREASE_4A4A",
            0x5A5A: "GREASE_5A5A",
            0x6A6A: "GREASE_6A6A",
            0x7A7A: "GREASE_7A7A",
            0x8A8A: "GREASE_8A8A",
            0x9A9A: "GREASE_9A9A",
            0xAAAA: "GREASE_AAAA",
            0xBABA: "GREASE_BABA",
            0xCACA: "GREASE_CACA",
            0xDADA: "GREASE_DADA",
            0xEAEA: "GREASE_EAEA",
            0xFAFA: "GREASE_FAFA",
        }

    def get_cipher_suite_name(self, cipher_suite_id: int) -> str:
        if cipher_suite_id in self.cipher_suites:
            return self.cipher_suites[cipher_suite_id]
        else:
            return f"UNKNOWN_{cipher_suite_id:04X}"

    def is_post_quantum(self, cipher_suite_id: int) -> bool:
        """Check if a cipher suite might be post-quantum related."""
        # TLS 1.3 suites and experimental PQC suites
        pqc_indicators = [0x1301, 0x1302, 0x1303, 0x1304, 0x1305]
        experimental_patterns = [0x1A1A, 0x4A4A, 0x5A5A, 0x8A8A, 0xDADA]

        return cipher_suite_id in pqc_indicators or cipher_suite_id in experimental_patterns

    def is_grease(self, cipher_suite_id: int) -> bool:
        """Check if a cipher suite ID is a GREASE value."""
        grease_pattern = cipher_suite_id & 0x0F0F
        return grease_pattern == 0x0A0A and (cipher_suite_id & 0xF0F0) == ((cipher_suite_id >> 4) & 0xF0F0)


class CipherSuiteAnalyzer:
    def __init__(self):
        self.db = CipherSuiteDatabase()
        self.results = {
            'total_packets': 0,
            'packets_with_cipher_suites': 0,
            'cipher_suite_counts': Counter(),
            'cipher_suite_details': {},
            'post_quantum_count': 0,
            'grease_count': 0,
            'unknown_count': 0
        }
        self._port_app_cache = {}

    def get_application_for_port(self, port: int) -> Optional[str]:
        if port in self._port_app_cache:
            return self._port_app_cache[port]

        try:
            # Run lsof command to find what's using the port
            result = subprocess.run(
                ['lsof', '-n', '-i', f':{port}'],
                capture_output=True,
                text=True,
                timeout=5  # 5 second timeout
            )

            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:  # First line is header
                    process_line = lines[1]
                    parts = process_line.split()
                    if parts:
                        app_name = parts[0]  # First column is COMMAND
                        self._port_app_cache[port] = app_name
                        return app_name

            self._port_app_cache[port] = None
            return None
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            self._port_app_cache[port] = None
            return None
        except Exception:
            self._port_app_cache[port] = None
            return None

    def parse_cipher_suite_id(self, id_string: Optional[str]) -> Optional[int]:
        """Parse a cipher suite ID string like '0x1301' to integer."""
        if not id_string or id_string == "null":
            return None

        try:
            if id_string.startswith('0x'):
                return int(id_string, 16)
            else:
                return int(id_string)
        except (ValueError, TypeError):
            return None

    def analyze_packet(self, packet: Dict[str, Any]) -> None:
        """Analyze a single packet for cipher suite information."""
        self.results['total_packets'] += 1

        cipher_suite_id_str = packet.get('cipher_suite_id')
        if cipher_suite_id_str and cipher_suite_id_str != "null":
            cipher_suite_id = self.parse_cipher_suite_id(cipher_suite_id_str)

            if cipher_suite_id is not None:
                self.results['packets_with_cipher_suites'] += 1
                self.results['cipher_suite_counts'][cipher_suite_id] += 1

                cipher_name = self.db.get_cipher_suite_name(cipher_suite_id)

                if cipher_suite_id not in self.results['cipher_suite_details']:
                    self.results['cipher_suite_details'][cipher_suite_id] = {
                        'name': cipher_name,
                        'count': 0,
                        'first_seen': packet.get('timestamp'),
                        'is_post_quantum': self.db.is_post_quantum(cipher_suite_id),
                        'is_grease': self.db.is_grease(cipher_suite_id),
                        'is_unknown': cipher_name.startswith('UNKNOWN_')
                    }

                details = self.results['cipher_suite_details'][cipher_suite_id]
                details['count'] += 1

                if details['is_post_quantum']:
                    self.results['post_quantum_count'] += 1
                if details['is_grease']:
                    self.results['grease_count'] += 1
                if details['is_unknown']:
                    self.results['unknown_count'] += 1
    def analyze_json_file(self, file_path: str) -> None:
        print(f"Analyzing cipher suites in: {file_path}")

        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            if isinstance(data, list):
                for packet in data:
                    self.analyze_packet(packet)
            else:
                print("Error: JSON file should contain a list of packets")
                return

        except FileNotFoundError:
            print(f"Error: File {file_path} not found")
            return
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in {file_path}: {e}")
            return
        except Exception as e:
            print(f"Error analyzing file: {e}")
            return

    def print_summary(self) -> None:
        """Print a comprehensive summary of the analysis."""
        print("\n" + "="*80)
        print("CIPHER SUITE ANALYSIS SUMMARY")
        print("="*80)

        print(f"Total packets analyzed: {self.results['total_packets']:,}")
        print(f"Packets with cipher suites: {self.results['packets_with_cipher_suites']:,}")
        print(f"Unique cipher suites found: {len(self.results['cipher_suite_details'])}")
        print()

        print("CIPHER SUITE BREAKDOWN:")
        print("-" * 50)

        # Sort cipher suites by count (descending)
        sorted_suites = sorted(
            self.results['cipher_suite_details'].items(),
            key=lambda x: x[1]['count'],
            reverse=True
        )

        for cipher_id, details in sorted_suites:
            percentage = (details['count'] / self.results['packets_with_cipher_suites']) * 100

            flags = []
            if details['is_post_quantum']:
                flags.append("PQC")
            if details['is_grease']:
                flags.append("GREASE") 
            if details['is_unknown']:
                flags.append("UNKNOWN")
            flag_str = f" [{', '.join(flags)}]" if flags else ""
            print(f"0x{cipher_id:04X}: {details['name']:<50} "
                  f"Count: {details['count']:>6,} ({percentage:5.1f}%){flag_str}")

        print()
        print("SPECIAL CATEGORIES:")
        print("-" * 30)
        print(f"Post-Quantum related: {self.results['post_quantum_count']:,}")
        print(f"GREASE values: {self.results['grease_count']:,}")
        print(f"Unknown cipher suites: {self.results['unknown_count']:,}")

    def export_results(self, output_file: str) -> None:
        """Export detailed results to a JSON file."""
        output_data = {
            'analysis_summary': {
                'total_packets': self.results['total_packets'],
                'packets_with_cipher_suites': self.results['packets_with_cipher_suites'],
                'unique_cipher_suites': len(self.results['cipher_suite_details']),
                'post_quantum_count': self.results['post_quantum_count'],
                'grease_count': self.results['grease_count'],
                'unknown_count': self.results['unknown_count']
            },
            'cipher_suites': {}
        }

        for cipher_id, details in self.results['cipher_suite_details'].items():
            output_data['cipher_suites'][f"0x{cipher_id:04X}"] = details

        try:
            with open(output_file, 'w') as f:
                json.dump(output_data, f, indent=2)
            print(f"\nDetailed results exported to: {output_file}")
        except Exception as e:
            print(f"Error exporting results: {e}")

    def filter_and_enrich_packets(self, input_file: str, output_file: str) -> None:
        """
        Filter packets with cipher suite IDs and enrich them with cipher suite names.

        Args:
            input_file: Path to the input JSON file
            output_file: Path to the output JSON file for filtered packets
        """
        print(f"Filtering and enriching packets from: {input_file}")

        try:
            with open(input_file, 'r') as f:
                data = json.load(f)

            if not isinstance(data, list):
                print("Error: JSON file should contain a list of packets")
                return

            filtered_packets = []

            for packet in data:
                cipher_suite_id_str = packet.get('cipher_suite_id')

                if cipher_suite_id_str and cipher_suite_id_str != "null":
                    cipher_suite_id = self.parse_cipher_suite_id(cipher_suite_id_str)

                    if cipher_suite_id is not None:
                        enriched_packet = packet.copy()

                        cipher_name = self.db.get_cipher_suite_name(cipher_suite_id)
                        enriched_packet['cipher_suite_name'] = cipher_name

                        src_port = packet.get('src_port')
                        dst_port = packet.get('dst_port')

                        application_info = {}
                        if src_port:
                            src_app = self.get_application_for_port(src_port)
                            application_info['src_application'] = src_app

                        if dst_port:
                            dst_app = self.get_application_for_port(dst_port)
                            application_info['dst_application'] = dst_app

                        enriched_packet['application_info'] = application_info

                        enriched_packet['cipher_suite_metadata'] = {
                            'is_post_quantum': self.db.is_post_quantum(cipher_suite_id),
                            'is_grease': self.db.is_grease(cipher_suite_id),
                            'is_unknown': cipher_name.startswith('UNKNOWN_'),
                            'cipher_suite_id_numeric': cipher_suite_id
                        }

                        filtered_packets.append(enriched_packet)

            with open(output_file, 'w') as f:
                json.dump(filtered_packets, f, indent=2)

            print(f"Filtered {len(filtered_packets):,} packets with cipher suites from {len(data):,} total packets")
            print(f"Enriched packets exported to: {output_file}")

            cipher_suite_counts = Counter()
            pqc_count = 0
            grease_count = 0
            unknown_count = 0
            applications = set()

            for packet in filtered_packets:
                cipher_id = packet['cipher_suite_metadata']['cipher_suite_id_numeric']
                cipher_suite_counts[cipher_id] += 1

                if packet['cipher_suite_metadata']['is_post_quantum']:
                    pqc_count += 1
                if packet['cipher_suite_metadata']['is_grease']:
                    grease_count += 1
                if packet['cipher_suite_metadata']['is_unknown']:
                    unknown_count += 1

                app_info = packet.get('application_info', {})
                if app_info.get('src_application'):
                    applications.add(app_info['src_application'])
                if app_info.get('dst_application'):
                    applications.add(app_info['dst_application'])

            print(f"\nFiltered data statistics:")
            print(f"- Unique cipher suites: {len(cipher_suite_counts)}")
            print(f"- Post-quantum related: {pqc_count:,}")
            print(f"- GREASE values: {grease_count:,}")
            print(f"- Unknown cipher suites: {unknown_count:,}")
            print(f"- Applications detected: {len(applications)} ({', '.join(sorted(filter(None, applications))) if applications else 'None'})")

        except FileNotFoundError:
            print(f"Error: File {input_file} not found")
            return
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in {input_file}: {e}")
            return
        except Exception as e:
            print(f"Error processing file: {e}")
            return


def main():
    """Main function for command-line usage."""
    parser = argparse.ArgumentParser(
        description="Analyze TLS cipher suites from packet capture JSON data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyze.py data/pcap/cipher_suite_analysis.json
  python analyze.py data/pcap/cipher_suite_analysis.json --output results.json
  python analyze.py data/pcap/cipher_suite_analysis.json --filter-output filtered_packets.json
  python analyze.py data/pcap/cipher_suite_analysis.json --quiet --filter-output filtered.json
        """
    )

    parser.add_argument(
        'input_file',
        help='Path to the JSON file containing packet data'
    )
    parser.add_argument(
        '--output', '-o',
        help='Export detailed analysis results to JSON file'
    )
    parser.add_argument(
        '--filter-output', '-f',
        help='Export filtered packets (only those with cipher suite IDs) with enriched data to JSON file'
    )
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress detailed output, show only summary'
    )
    args = parser.parse_args()

    analyzer = CipherSuiteAnalyzer()
    analyzer.analyze_json_file(args.input_file)

    if not args.quiet:
        analyzer.print_summary()

    if args.output:
        analyzer.export_results(args.output)

    if args.filter_output:
        analyzer.filter_and_enrich_packets(args.input_file, args.filter_output)
    if analyzer.results['post_quantum_count'] > 0:

        print(f"\nPost-Quantum Cryptography indicators found: {analyzer.results['post_quantum_count']:,} occurrences")

    if analyzer.results['unknown_count'] > 0:
        print(f"Unknown cipher suites found: {analyzer.results['unknown_count']:,} occurrences - may need database updates")


if __name__ == "__main__":
    main()
