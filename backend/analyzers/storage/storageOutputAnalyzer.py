#!/usr/bin/env python3
"""
SSH Key Analysis Tool for PQC Storage Discovery
Analyzes SSH key data and evaluates cryptographic algorithms for post-quantum readiness.
"""

import json
import argparse
import sys
import base64
import hashlib
import re
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Any, Set
from datetime import datetime


class SSHKeyDatabase:
    def __init__(self):
        self.key_types = {
            'ssh-ed25519': {
                'name': 'Ed25519',
                'security_level': 'high',
                'quantum_resistant': True,
                'key_size': 256,
                'description': 'Edwards-curve Digital Signature Algorithm using Curve25519'
            },
            # Classical algorithms - vulnerable to quantum attacks
            'ssh-rsa': {
                'name': 'RSA',
                'security_level': 'medium',
                'quantum_resistant': False,
                'key_size': None,  # Variable, determined by key content
                'description': 'RSA public key algorithm'
            },
            'rsa-sha2-256': {
                'name': 'RSA-SHA2-256',
                'security_level': 'medium',
                'quantum_resistant': False,
                'key_size': None,
                'description': 'RSA with SHA-256 signature algorithm'
            },
            'rsa-sha2-512': {
                'name': 'RSA-SHA2-512',
                'security_level': 'medium',
                'quantum_resistant': False,
                'key_size': None,
                'description': 'RSA with SHA-512 signature algorithm'
            },
            # ECDSA algorithms - vulnerable to quantum attacks
            'ecdsa-sha2-nistp256': {
                'name': 'ECDSA P-256',
                'security_level': 'medium',
                'quantum_resistant': False,
                'key_size': 256,
                'description': 'Elliptic Curve DSA using NIST P-256 curve'
            },
            'ecdsa-sha2-nistp384': {
                'name': 'ECDSA P-384',
                'security_level': 'medium',
                'quantum_resistant': False,
                'key_size': 384,
                'description': 'Elliptic Curve DSA using NIST P-384 curve'
            },
            'ecdsa-sha2-nistp521': {
                'name': 'ECDSA P-521',
                'security_level': 'medium',
                'quantum_resistant': False,
                'key_size': 521,
                'description': 'Elliptic Curve DSA using NIST P-521 curve'
            },
            # Deprecated/weak algorithms
            'ssh-dss': {
                'name': 'DSA',
                'security_level': 'low',
                'quantum_resistant': False,
                'key_size': 1024,
                'description': 'Digital Signature Algorithm (deprecated)'
            },
            'ssh-dsa': {
                'name': 'DSA',
                'security_level': 'low',
                'quantum_resistant': False,
                'key_size': 1024,
                'description': 'Digital Signature Algorithm (deprecated)'
            }
        }

        self.rsa_security_levels = {
            (0, 1024): 'very_low',
            (1024, 2048): 'low',
            (2048, 3072): 'medium',
            (3072, 4096): 'high',
            (4096, float('inf')): 'very_high'
        }

    def get_key_info(self, key_type: str) -> Dict[str, Any]:
        """Get information about a key type."""
        return self.key_types.get(key_type, {
            'name': f'Unknown ({key_type})',
            'security_level': 'unknown',
            'quantum_resistant': None,
            'key_size': None,
            'description': f'Unrecognized key type: {key_type}'
        })

    def analyze_rsa_key_size(self, key_data: str) -> int:
        """Extract RSA key size from key data."""
        try:
            decoded = base64.b64decode(key_data)

            if len(decoded) < 4:
                return 0

            key_length = len(decoded)

            if key_length < 200:
                return 1024
            elif key_length < 400:
                return 2048
            elif key_length < 600:
                return 3072
            elif key_length < 800:
                return 4096
            else:
                return 8192

        except Exception:
            return 0

    def get_rsa_security_level(self, key_size: int) -> str:
        """Determine security level based on RSA key size."""
        for (min_size, max_size), level in self.rsa_security_levels.items():
            if min_size <= key_size < max_size:
                return level
        return 'unknown'

    def is_deprecated(self, key_type: str) -> bool:
        """Check if a key type is deprecated."""
        deprecated_types = ['ssh-dss', 'ssh-dsa']
        return key_type in deprecated_types

    def get_quantum_resistance_status(self, key_type: str) -> str:
        """Get quantum resistance status for a key type."""
        info = self.get_key_info(key_type)
        if info['quantum_resistant'] is True:
            return 'resistant'
        elif info['quantum_resistant'] is False:
            return 'vulnerable'
        else:
            return 'unknown'


class SSHKeyAnalyzer:
    def __init__(self):
        self.db = SSHKeyDatabase()
        self.results = {
            'total_keys': 0,
            'total_hosts': 0,
            'unique_hosts': set(),
            'key_type_counts': Counter(),
            'security_levels': Counter(),
            'quantum_resistance': Counter(),
            'deprecated_keys': 0,
            'rsa_key_sizes': Counter(),
            'key_details': {},
            'host_analysis': defaultdict(list),
            'duplicate_keys': defaultdict(list),
            'security_issues': []
        }

    def analyze_ssh_key(self, key_entry: Dict[str, Any], file_path: str = "") -> None:
        key_type = key_entry.get('key_type', 'unknown')
        raw_key = key_entry.get('raw_key', '')
        hosts = key_entry.get('hosts', [])
        line_number = key_entry.get('line_number', 0)


        self.results['total_keys'] += 1
        self.results['key_type_counts'][key_type] += 1

        for host in hosts:
            self.results['unique_hosts'].add(host)
            self.results['host_analysis'][host].append({
                'key_type': key_type,
                'line_number': line_number,
                'file_path': file_path
            })

        key_info = self.db.get_key_info(key_type)
        security_level = key_info['security_level']

        if key_type.startswith('ssh-rsa') or key_type.startswith('rsa-'):
            rsa_size = self.db.analyze_rsa_key_size(raw_key)
            self.results['rsa_key_sizes'][rsa_size] += 1

            if rsa_size > 0:
                rsa_security = self.db.get_rsa_security_level(rsa_size)
                security_level = rsa_security

                if rsa_size < 2048:
                    self.results['security_issues'].append({
                        'type': 'weak_rsa_key',
                        'severity': 'high',
                        'hosts': hosts,
                        'key_type': key_type,
                        'key_size': rsa_size,
                        'message': f'RSA key with {rsa_size} bits is below recommended 2048-bit minimum',
                        'line_number': line_number,
                        'file_path': file_path
                    })

        self.results['security_levels'][security_level] += 1

        quantum_status = self.db.get_quantum_resistance_status(key_type)
        self.results['quantum_resistance'][quantum_status] += 1

        if self.db.is_deprecated(key_type):
            self.results['deprecated_keys'] += 1
            self.results['security_issues'].append({
                'type': 'deprecated_algorithm',
                'severity': 'medium',
                'hosts': hosts,
                'key_type': key_type,
                'message': f'Key type {key_type} is deprecated and should be replaced',
                'line_number': line_number,
                'file_path': file_path
            })

        key_id = f"{key_type}:{raw_key[:32]}..."
        if key_id not in self.results['key_details']:
            self.results['key_details'][key_id] = {
                'key_type': key_type,
                'security_level': security_level,
                'quantum_resistant': key_info['quantum_resistant'],
                'hosts': [],
                'count': 0,
                'first_seen_line': line_number,
                'first_seen_file': file_path
            }

        self.results['key_details'][key_id]['hosts'].extend(hosts)
        self.results['key_details'][key_id]['count'] += 1

        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()[:16]
        self.results['duplicate_keys'][key_hash].append({
            'hosts': hosts,
            'key_type': key_type,
            'line_number': line_number,
            'file_path': file_path
        })

    def analyze_json_file(self, file_path: str) -> None:
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            if isinstance(data, dict) and 'files' in data:
                for file_entry in data['files']:
                    entries = file_entry.get('entries', [])
                    file_metadata = file_entry.get('file_metadata', {})
                    source_file = file_metadata.get('path', file_path)

                    for entry in entries:
                        self.analyze_ssh_key(entry, source_file)
            elif isinstance(data, list):
                for entry in data:
                    self.analyze_ssh_key(entry, file_path)
            elif isinstance(data, dict) and 'key_type' in data:
                self.analyze_ssh_key(data, file_path)
            else:
                print("Error: Unrecognized JSON structure")
                return

            self.results['total_hosts'] = len(self.results['unique_hosts'])

        except FileNotFoundError:
            print(f"Error: File {file_path} not found")
            return
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in {file_path}: {e}")
            return
        except Exception as e:
            print(f"Error analyzing file: {e}")
            return

    def detect_duplicate_keys(self) -> List[Dict[str, Any]]:
        duplicates = []

        for key_hash, occurrences in self.results['duplicate_keys'].items():
            if len(occurrences) > 1:
                all_hosts = set()
                for occurrence in occurrences:
                    all_hosts.update(occurrence['hosts'])

                if len(all_hosts) > 1:
                    duplicates.append({
                        'key_hash': key_hash,
                        'hosts': list(all_hosts),
                        'occurrences': len(occurrences),
                        'key_type': occurrences[0]['key_type']
                    })
        return duplicates

    def print_summary(self) -> None:
        """Print a comprehensive summary of the SSH key analysis."""
        print("\n" + "="*80)
        print("SSH KEY CRYPTOGRAPHIC ANALYSIS SUMMARY")
        print("="*80)

        print(f"Total SSH keys analyzed: {self.results['total_keys']:,}")
        print(f"Unique hosts: {self.results['total_hosts']:,}")
        print(f"Key types found: {len(self.results['key_type_counts'])}")
        print()

        print("KEY TYPE DISTRIBUTION:")
        print("-" * 40)
        for key_type, count in self.results['key_type_counts'].most_common():
            percentage = (count / self.results['total_keys']) * 100
            key_info = self.db.get_key_info(key_type)
            quantum_indicator = "🟢" if key_info['quantum_resistant'] else "🔴" if key_info['quantum_resistant'] is False else "⚪"
            print(f"{quantum_indicator} {key_type:<25} Count: {count:>4} ({percentage:5.1f}%) - {key_info['name']}")

        print()
        print("SECURITY LEVEL DISTRIBUTION:")
        print("-" * 35)
        for level, count in self.results['security_levels'].most_common():
            percentage = (count / self.results['total_keys']) * 100
            level_indicator = {
                'very_high': '🟢',
                'high': '🟢', 
                'medium': '🟡',
                'low': '🟠',
                'very_low': '🔴',
                'unknown': '⚪'
            }.get(level, '⚪')
            print(f"{level_indicator} {level:<12} Count: {count:>4} ({percentage:5.1f}%)")

        print()
        print("POST-QUANTUM CRYPTOGRAPHY READINESS:")
        print("-" * 45)
        for status, count in self.results['quantum_resistance'].most_common():
            percentage = (count / self.results['total_keys']) * 100
            status_indicator = {
                'resistant': '🟢',
                'vulnerable': '🔴',
                'unknown': '⚪'
            }.get(status, '⚪')
            print(f"{status_indicator} {status:<12} Count: {count:>4} ({percentage:5.1f}%)")

        if self.results['rsa_key_sizes']:
            print()
            print("RSA KEY SIZE DISTRIBUTION:")
            print("-" * 30)
            for size, count in sorted(self.results['rsa_key_sizes'].items()):
                security = self.db.get_rsa_security_level(size)
                size_indicator = {
                    'very_high': '🟢',
                    'high': '🟢',
                    'medium': '🟡', 
                    'low': '🟠',
                    'very_low': '🔴'
                }.get(security, '⚪')
                print(f"{size_indicator} {size:>4} bits: {count:>4} keys ({security})")

        if self.results['security_issues']:
            print()
            print("SECURITY ISSUES DETECTED:")
            print("-" * 30)
            issue_counts = Counter(issue['type'] for issue in self.results['security_issues'])
            for issue_type, count in issue_counts.items():
                print(f"{issue_type.replace('_', ' ').title()}: {count} occurrences")

        duplicates = self.detect_duplicate_keys()
        if duplicates:
            print()
            print("DUPLICATE KEYS ACROSS HOSTS:")
            print("-" * 35)
            print(f"Found {len(duplicates)} keys used across multiple hosts")
            for dup in duplicates[:5]:
                print(f"   Key ({dup['key_type']}): {len(dup['hosts'])} hosts")

        print()
        print("RECOMMENDATIONS:")
        print("-" * 20)

        vulnerable_count = self.results['quantum_resistance']['vulnerable']
        if vulnerable_count > 0:
            print(f"{vulnerable_count} keys are vulnerable to quantum attacks")
            print("   → Migrate to Ed25519 for quantum resistance")

        if self.results['deprecated_keys'] > 0:
            print(f"{self.results['deprecated_keys']} deprecated key types found")
            print("   → Replace DSA keys immediately")

        weak_rsa = sum(count for size, count in self.results['rsa_key_sizes'].items() if size < 2048)
        if weak_rsa > 0:
            print(f"{weak_rsa} RSA keys below 2048 bits")
            print("   → Upgrade to RSA-2048+ or preferably Ed25519")

        if len(self.results['quantum_resistance']) > 0:
            resistant_pct = (self.results['quantum_resistance']['resistant'] / self.results['total_keys']) * 100
            print(f"{resistant_pct:.1f}% of keys are quantum-resistant")

    def export_results(self, output_file: str) -> None:
        export_data = {
            'analysis_summary': {
                'total_keys': self.results['total_keys'],
                'total_hosts': self.results['total_hosts'],
                'unique_host_list': list(self.results['unique_hosts']),
                'analysis_timestamp': datetime.now().isoformat()
            },
            'key_type_distribution': dict(self.results['key_type_counts']),
            'security_levels': dict(self.results['security_levels']),
            'quantum_resistance': dict(self.results['quantum_resistance']),
            'rsa_key_sizes': dict(self.results['rsa_key_sizes']),
            'deprecated_keys': self.results['deprecated_keys'],
            'security_issues': self.results['security_issues'],
            'duplicate_keys': self.detect_duplicate_keys(),
            'key_details': self.results['key_details'],
            'host_analysis': {host: keys for host, keys in self.results['host_analysis'].items()}
        }

        try:
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            print(f"\nDetailed analysis results exported to: {output_file}")
        except Exception as e:
            print(f"Error exporting results: {e}")

    def filter_and_enrich_keys(self, input_file: str, output_file: str) -> None:
        """Filter and enrich SSH key data with security analysis."""
        print(f"Filtering and enriching SSH key data from: {input_file}")

        try:
            with open(input_file, 'r') as f:
                data = json.load(f)

            enriched_data = data.copy()

            enriched_data['analysis_metadata'] = {
                'analyzed_at': datetime.now().isoformat(),
                'total_keys_analyzed': self.results['total_keys'],
                'security_summary': dict(self.results['security_levels']),
                'quantum_resistance_summary': dict(self.results['quantum_resistance'])
            }
            if 'files' in enriched_data:
                for file_entry in enriched_data['files']:
                    if 'entries' in file_entry:
                        for entry in file_entry['entries']:
                            key_type = entry.get('key_type', 'unknown')
                            raw_key = entry.get('raw_key', '')
                            key_info = self.db.get_key_info(key_type)
                            entry['security_analysis'] = {
                                'algorithm_name': key_info['name'],
                                'security_level': key_info['security_level'],
                                'quantum_resistant': key_info['quantum_resistant'],
                                'is_deprecated': self.db.is_deprecated(key_type),
                                'description': key_info['description']
                            }
                            if key_type.startswith('ssh-rsa'):
                                rsa_size = self.db.analyze_rsa_key_size(raw_key)
                                entry['security_analysis'].update({
                                    'rsa_key_size': rsa_size,
                                    'rsa_security_level': self.db.get_rsa_security_level(rsa_size)
                                })
            with open(output_file, 'w') as f:
                json.dump(enriched_data, f, indent=2)
            print(f"Enriched SSH key data exported to: {output_file}")
        except Exception as e:
            print(f"Error processing file: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze SSH keys for cryptographic security and post-quantum readiness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python storageOutputAnalyzer.py ssh_known_hosts_inventory.json
  python storageOutputAnalyzer.py ssh_keys.json --output security_analysis.json
  python storageOutputAnalyzer.py ssh_keys.json --enrich-output enriched_keys.json
  python storageOutputAnalyzer.py ssh_keys.json --quiet --output results.json
        """
    )

    parser.add_argument(
        'input_file',
        help='Path to the JSON file containing SSH key data'
    )
    parser.add_argument(
        '--output', '-o',
        help='Export detailed analysis results to JSON file'
    )
    parser.add_argument(
        '--enrich-output', '-e',
        help='Export enriched SSH key data with security analysis to JSON file'
    )
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress detailed output, show only summary'
    )

    args = parser.parse_args()

    analyzer = SSHKeyAnalyzer()
    analyzer.analyze_json_file(args.input_file)

    if not args.quiet:
        analyzer.print_summary()

    if args.output:
        analyzer.export_results(args.output)

    if args.enrich_output:
        analyzer.filter_and_enrich_keys(args.input_file, args.enrich_output)

    if analyzer.results['quantum_resistance']['vulnerable'] > 0:
        print(f"\nWarning: {analyzer.results['quantum_resistance']['vulnerable']} keys vulnerable to quantum attacks")

    if analyzer.results['deprecated_keys'] > 0:
        print(f"Warning: {analyzer.results['deprecated_keys']} deprecated key algorithms found")

if __name__ == "__main__":
    main()