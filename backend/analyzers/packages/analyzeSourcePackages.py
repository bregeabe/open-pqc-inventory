import os
import json
import re
import argparse
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Set, Optional, Any, Tuple
from datetime import datetime


class CryptographicLibraryDatabase:
    def __init__(self):

        self.libraries = {
            # JavaScript/TypeScript/Node.js
            'javascript': {
                'extensions': ['.js', '.jsx', '.ts', '.tsx', '.mjs'],
                'import_patterns': [
                    r'import\s+.*?from\s+[\'"]([^\'\"]+)[\'"]',
                    r'require\s*\(\s*[\'"]([^\'\"]+)[\'"]\s*\)',
                    r'import\s*\(\s*[\'"]([^\'\"]+)[\'"]\s*\)'
                ],
                'libraries': {
                    'crypto-js': {'severity': 'medium', 'pqc_ready': False},
                    'node-forge': {'severity': 'medium', 'pqc_ready': False},
                    'forge': {'severity': 'medium', 'pqc_ready': False},
                    'jsencrypt': {'severity': 'medium', 'pqc_ready': False},
                    'crypto-browserify': {'severity': 'medium', 'pqc_ready': False},
                    'webcrypto-core': {'severity': 'medium', 'pqc_ready': False},
                    'libsodium-js': {'severity': 'high', 'pqc_ready': True},
                    'libsodium.js': {'severity': 'high', 'pqc_ready': True},
                    'tweetnacl': {'severity': 'high', 'pqc_ready': True},
                    'tweetnacl-js': {'severity': 'high', 'pqc_ready': True},
                    'js-nacl': {'severity': 'high', 'pqc_ready': True},
                    'sjcl': {'severity': 'medium', 'pqc_ready': False},
                    'asmcrypto': {'severity': 'medium', 'pqc_ready': False},
                    'noble-ciphers': {'severity': 'high', 'pqc_ready': True},
                    'noble-curves': {'severity': 'high', 'pqc_ready': True},
                    'noble-hashes': {'severity': 'high', 'pqc_ready': True},
                    'noble-post-quantum': {'severity': 'high', 'pqc_ready': True},
                    'noble-secp256k1': {'severity': 'high', 'pqc_ready': False},
                    'noble-ed25519': {'severity': 'high', 'pqc_ready': True},
                    'openpgp': {'severity': 'medium', 'pqc_ready': False},
                    'bcrypt': {'severity': 'medium', 'pqc_ready': False},
                    'bcryptjs': {'severity': 'medium', 'pqc_ready': False},
                    'scrypt': {'severity': 'medium', 'pqc_ready': False},
                    'argon2': {'severity': 'high', 'pqc_ready': False},
                    'milagro-crypto-js': {'severity': 'medium', 'pqc_ready': False}
                }
            },
            
            # Python
            'python': {
                'extensions': ['.py', '.pyx', '.pyi'],
                'import_patterns': [
                    r'from\s+([a-zA-Z_][a-zA-Z0-9_\.]*)\s+import',
                    r'import\s+([a-zA-Z_][a-zA-Z0-9_\.]*)',
                ],
                'libraries': {
                    'cryptography': {'severity': 'high', 'pqc_ready': True},
                    'pycryptodome': {'severity': 'high', 'pqc_ready': False},
                    'pycrypto': {'severity': 'low', 'pqc_ready': False},
                    'pynacl': {'severity': 'high', 'pqc_ready': True},
                    'cryptopy': {'severity': 'medium', 'pqc_ready': False},
                    'pyopenssl': {'severity': 'medium', 'pqc_ready': False},
                    'paramiko': {'severity': 'medium', 'pqc_ready': False},
                    'bcrypt': {'severity': 'medium', 'pqc_ready': False},
                    'scrypt': {'severity': 'medium', 'pqc_ready': False},
                    'argon2': {'severity': 'high', 'pqc_ready': False},
                    'hashlib': {'severity': 'medium', 'pqc_ready': False},
                    'hmac': {'severity': 'medium', 'pqc_ready': False},
                    'secrets': {'severity': 'medium', 'pqc_ready': False},
                    'ecdsa': {'severity': 'medium', 'pqc_ready': False},
                    'rsa': {'severity': 'medium', 'pqc_ready': False},
                    'charm': {'severity': 'medium', 'pqc_ready': False},
                    'pyelliptic': {'severity': 'medium', 'pqc_ready': False}
                }
            },
            
            # Java
            'java': {
                'extensions': ['.java'],
                'import_patterns': [
                    r'import\s+([a-zA-Z_][a-zA-Z0-9_\.]*)',
                ],
                'libraries': {
                    'org.bouncycastle': {'severity': 'high', 'pqc_ready': True},
                    'javax.crypto': {'severity': 'medium', 'pqc_ready': False},
                    'java.security': {'severity': 'medium', 'pqc_ready': False},
                    'org.apache.shiro': {'severity': 'medium', 'pqc_ready': False},
                    'com.google.tink': {'severity': 'high', 'pqc_ready': True},
                    'org.abstractj.kalium': {'severity': 'high', 'pqc_ready': True},
                    'org.mindrot.jbcrypt': {'severity': 'medium', 'pqc_ready': False},
                    'com.lambdaworks.crypto': {'severity': 'medium', 'pqc_ready': False},
                }
            },
            
            # C/C++
            'c_cpp': {
                'extensions': ['.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx'],
                'import_patterns': [
                    r'#include\s*[<"]([^>"]+)[">]',
                ],
                'libraries': {
                    'openssl': {'severity': 'high', 'pqc_ready': True},
                    'libsodium': {'severity': 'high', 'pqc_ready': True},
                    'libgcrypt': {'severity': 'medium', 'pqc_ready': False},
                    'nettle': {'severity': 'medium', 'pqc_ready': False},
                    'botan': {'severity': 'high', 'pqc_ready': True},
                    'cryptopp': {'severity': 'medium', 'pqc_ready': False},
                    'crypto++': {'severity': 'medium', 'pqc_ready': False},
                    'nacl': {'severity': 'high', 'pqc_ready': True},
                    'tweetnacl': {'severity': 'high', 'pqc_ready': True},
                    'mbedtls': {'severity': 'medium', 'pqc_ready': False},
                    'polarssl': {'severity': 'low', 'pqc_ready': False},
                    'wolfssl': {'severity': 'medium', 'pqc_ready': False},
                    'libtomcrypt': {'severity': 'medium', 'pqc_ready': False},
                    'rhash': {'severity': 'medium', 'pqc_ready': False}
                }
            },
            
            # Go
            'go': {
                'extensions': ['.go'],
                'import_patterns': [
                    r'import\s+[\'"]([^\'\"]+)[\'"]',
                    r'import\s+\w+\s+[\'"]([^\'\"]+)[\'"]',
                ],
                'libraries': {
                    'crypto': {'severity': 'medium', 'pqc_ready': False},
                    'crypto/aes': {'severity': 'medium', 'pqc_ready': False},
                    'crypto/rsa': {'severity': 'medium', 'pqc_ready': False},
                    'crypto/ecdsa': {'severity': 'medium', 'pqc_ready': False},
                    'crypto/ed25519': {'severity': 'high', 'pqc_ready': True},
                    'crypto/sha256': {'severity': 'medium', 'pqc_ready': False},
                    'crypto/tls': {'severity': 'medium', 'pqc_ready': False},
                    'golang.org/x/crypto': {'severity': 'medium', 'pqc_ready': False},
                    'github.com/dedis/kyber': {'severity': 'high', 'pqc_ready': True},
                    'go.dedis.ch/kyber': {'severity': 'high', 'pqc_ready': True}
                }
            },
            
            # Rust
            'rust': {
                'extensions': ['.rs'],
                'import_patterns': [
                    r'use\s+([a-zA-Z_][a-zA-Z0-9_:]*)',
                    r'extern\s+crate\s+([a-zA-Z_][a-zA-Z0-9_]*)',
                ],
                'libraries': {
                    'ring': {'severity': 'high', 'pqc_ready': True},
                    'rustls': {'severity': 'high', 'pqc_ready': True},
                    'sodiumoxide': {'severity': 'high', 'pqc_ready': True},
                    'rust-crypto': {'severity': 'medium', 'pqc_ready': False},
                    'openssl': {'severity': 'medium', 'pqc_ready': True},
                    'orion': {'severity': 'high', 'pqc_ready': True},
                    'dalek-cryptography': {'severity': 'high', 'pqc_ready': True},
                    'x25519-dalek': {'severity': 'high', 'pqc_ready': True},
                    'ed25519-dalek': {'severity': 'high', 'pqc_ready': True},
                    'curve25519-dalek': {'severity': 'high', 'pqc_ready': True}
                }
            },
            
            # C#
            'csharp': {
                'extensions': ['.cs'],
                'import_patterns': [
                    r'using\s+([a-zA-Z_][a-zA-Z0-9_\.]*)',
                ],
                'libraries': {
                    'System.Security.Cryptography': {'severity': 'medium', 'pqc_ready': False},
                    'Org.BouncyCastle': {'severity': 'high', 'pqc_ready': True},
                    'libsodium-net': {'severity': 'high', 'pqc_ready': True},
                    'SecurityDriven.Inferno': {'severity': 'high', 'pqc_ready': False},
                    'StreamCryptor': {'severity': 'medium', 'pqc_ready': True}
                }
            },
            
            # PHP
            'php': {
                'extensions': ['.php'],
                'import_patterns': [
                    r'require_once\s*\(\s*[\'"]([^\'\"]+)[\'"]\s*\)',
                    r'require\s*\(\s*[\'"]([^\'\"]+)[\'"]\s*\)',
                    r'include_once\s*\(\s*[\'"]([^\'\"]+)[\'"]\s*\)',
                    r'include\s*\(\s*[\'"]([^\'\"]+)[\'"]\s*\)',
                    r'use\s+([a-zA-Z_][a-zA-Z0-9_\\]*)',
                ],
                'libraries': {
                    'openssl': {'severity': 'medium', 'pqc_ready': True},
                    'sodium': {'severity': 'high', 'pqc_ready': True},
                    'libsodium': {'severity': 'high', 'pqc_ready': True},
                    'halite': {'severity': 'high', 'pqc_ready': True},
                    'defuse/php-encryption': {'severity': 'high', 'pqc_ready': False}
                }
            },
            
            # Ruby  
            'ruby': {
                'extensions': ['.rb'],
                'import_patterns': [
                    r'require\s+[\'"]([^\'\"]+)[\'"]',
                    r'require_relative\s+[\'"]([^\'\"]+)[\'"]',
                    r'gem\s+[\'"]([^\'\"]+)[\'"]',
                ],
                'libraries': {
                    'openssl': {'severity': 'medium', 'pqc_ready': True},
                    'rbnacl': {'severity': 'high', 'pqc_ready': True},
                    'bcrypt': {'severity': 'medium', 'pqc_ready': False},
                    'digest': {'severity': 'medium', 'pqc_ready': False}
                }
            },
            
            # Swift
            'swift': {
                'extensions': ['.swift'],
                'import_patterns': [
                    r'import\s+([a-zA-Z_][a-zA-Z0-9_]*)',
                ],
                'libraries': {
                    'CryptoSwift': {'severity': 'medium', 'pqc_ready': False},
                    'CommonCrypto': {'severity': 'medium', 'pqc_ready': False},
                    'Sodium': {'severity': 'high', 'pqc_ready': True},
                    'SwiftSodium': {'severity': 'high', 'pqc_ready': True}
                }
            }
        }
        

        self.package_files = {
            'package.json': {
                'language': 'javascript',
                'dependency_patterns': [

                ]
            },
            'requirements.txt': {
                'language': 'python', 
                'dependency_patterns': [


                ]
            },
            'Pipfile': {
                'language': 'python',
                'dependency_patterns': [

                ]
            },
            'poetry.lock': {
                'language': 'python',
                'dependency_patterns': [

                ]
            },
            'Cargo.toml': {
                'language': 'rust',
                'dependency_patterns': [

                ]
            },
            'go.mod': {
                'language': 'go',
                'dependency_patterns': [


                ]
            },
            'composer.json': {
                'language': 'php',
                'dependency_patterns': [

                ]
            },
            'Gemfile': {
                'language': 'ruby',
                'dependency_patterns': [

                ]
            }
        }

    def get_language_info(self, language: str) -> Optional[Dict]:
        """Get language configuration."""
        return self.libraries.get(language)

    def is_crypto_library(self, library_name: str, language: str) -> Optional[Dict]:
        """Check if a library is a known cryptographic library."""
        lang_info = self.get_language_info(language)
        if not lang_info:
            return None
            

        if library_name in lang_info['libraries']:
            return lang_info['libraries'][library_name]
            

        for known_lib in lang_info['libraries']:
            if known_lib in library_name or library_name in known_lib:
                return lang_info['libraries'][known_lib]
                
        return None


class SourceCodeAnalyzer:
    def __init__(self):
        self.db = CryptographicLibraryDatabase()
        self.results = {
            'scan_metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_files_scanned': 0,
                'files_with_crypto': 0,
                'languages_detected': set(),
                'crypto_libraries_found': set()
            },
            'crypto_usage': [],
            'package_dependencies': [],
            'summary_by_language': defaultdict(lambda: {
                'files_count': 0,
                'crypto_files_count': 0,
                'libraries_used': set(),
                'security_levels': Counter(),
                'pqc_ready_count': 0
            }),
            'security_analysis': {
                'high_risk_files': [],
                'deprecated_libraries': [],
                'non_pqc_ready': []
            }
        }

    def get_file_language(self, file_path: Path) -> Optional[str]:
        """Determine programming language based on file extension."""
        ext = file_path.suffix.lower()
        
        for lang, info in self.db.libraries.items():
            if ext in info['extensions']:
                return lang
        return None

    def analyze_source_file(self, file_path: Path) -> List[Dict]:
        """Analyze a single source file for cryptographic library usage."""
        language = self.get_file_language(file_path)
        if not language:
            return []
            
        lang_info = self.db.get_language_info(language)
        if not lang_info:
            return []
            
        crypto_findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                

            for pattern in lang_info['import_patterns']:
                for line_num, line in enumerate(lines, 1):
                    matches = re.findall(pattern, line, re.IGNORECASE)
                    for match in matches:

                        library_name = match.split('.')[0].split('/')[0]
                        
                        crypto_info = self.db.is_crypto_library(library_name, language)
                        if crypto_info:
                            finding = {
                                'file_path': str(file_path),
                                'language': language,
                                'library_name': match,
                                'library_base': library_name,
                                'line_number': line_num,
                                'line_content': line.strip(),
                                'import_type': 'import',
                                'severity': crypto_info['severity'],
                                'pqc_ready': crypto_info['pqc_ready'],
                                'pattern_matched': pattern
                            }
                            crypto_findings.append(finding)
                            

                            self.results['scan_metadata']['crypto_libraries_found'].add(library_name)
                            self.results['scan_metadata']['languages_detected'].add(language)
                            
        except Exception as e:
            print(f"Error analyzing {file_path}: {e}")
            
        return crypto_findings

    def analyze_package_file(self, file_path: Path) -> List[Dict]:
        """Analyze package manager files for cryptographic dependencies."""
        filename = file_path.name
        if filename not in self.db.package_files:
            return []
            
        pkg_info = self.db.package_files[filename]
        language = pkg_info['language']
        lang_info = self.db.get_language_info(language)
        if not lang_info:
            return []
            
        crypto_findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
            for pattern in pkg_info['dependency_patterns']:
                for line_num, line in enumerate(lines, 1):
                    matches = re.findall(pattern, line, re.IGNORECASE)
                    for match in matches:
                        library_name = match.split('.')[0].split('/')[0]
                        
                        crypto_info = self.db.is_crypto_library(library_name, language)
                        if crypto_info:
                            finding = {
                                'file_path': str(file_path),
                                'language': language,
                                'library_name': match,
                                'library_base': library_name,
                                'line_number': line_num,
                                'line_content': line.strip(),
                                'import_type': 'dependency',
                                'severity': crypto_info['severity'],
                                'pqc_ready': crypto_info['pqc_ready'],
                                'package_file': filename
                            }
                            crypto_findings.append(finding)
                            
        except Exception as e:
            print(f"Error analyzing package file {file_path}: {e}")
            
        return crypto_findings

    def scan_directory(self, directory: str, recursive: bool = True) -> None:
        """Scan directory for source files and package files."""
        directory_path = Path(directory).expanduser().resolve()
        
        if not directory_path.exists() or not directory_path.is_dir():
            raise ValueError(f"Invalid directory: {directory_path}")
            

        all_extensions = set()
        for lang_info in self.db.libraries.values():
            all_extensions.update(lang_info['extensions'])
            

        package_files = set(self.db.package_files.keys())
        
        print(f"Scanning directory: {directory_path}")
        
        if recursive:
            file_iterator = directory_path.rglob('*')
        else:
            file_iterator = directory_path.iterdir()
            
        for file_path in file_iterator:
            if not file_path.is_file():
                continue
                
            self.results['scan_metadata']['total_files_scanned'] += 1
            

            if any(ignore in str(file_path) for ignore in [
                'node_modules', '.git', '__pycache__', 'target/debug',
                'target/release', 'build', 'dist', '.tox', 'venv'
            ]):
                continue
                
            findings = []
            

            if file_path.suffix.lower() in all_extensions:
                findings = self.analyze_source_file(file_path)
                

            elif file_path.name in package_files:
                findings = self.analyze_package_file(file_path)
                
            if findings:
                self.results['scan_metadata']['files_with_crypto'] += 1
                
                for finding in findings:
                    if finding['import_type'] == 'import':
                        self.results['crypto_usage'].append(finding)
                    else:
                        self.results['package_dependencies'].append(finding)
                        

                    lang = finding['language']
                    summary = self.results['summary_by_language'][lang]
                    summary['libraries_used'].add(finding['library_base'])
                    summary['security_levels'][finding['severity']] += 1
                    if finding['pqc_ready']:
                        summary['pqc_ready_count'] += 1
                        

                    if finding['severity'] == 'low':
                        if finding not in self.results['security_analysis']['high_risk_files']:
                            self.results['security_analysis']['high_risk_files'].append(finding)
                            
                    if not finding['pqc_ready']:
                        if finding not in self.results['security_analysis']['non_pqc_ready']:
                            self.results['security_analysis']['non_pqc_ready'].append(finding)
                            

            language = self.get_file_language(file_path)
            if language:
                summary = self.results['summary_by_language'][language]
                summary['files_count'] += 1
                if findings:
                    summary['crypto_files_count'] += 1

    def print_summary(self) -> None:
        """Print analysis summary."""
        metadata = self.results['scan_metadata']
        
        print("\n" + "="*80)
        print("SOURCE CODE CRYPTOGRAPHIC LIBRARY ANALYSIS")
        print("="*80)
        
        print(f"Files scanned: {metadata['total_files_scanned']:,}")
        print(f"Files with crypto usage: {metadata['files_with_crypto']:,}")
        print(f"Programming languages detected: {len(metadata['languages_detected'])}")
        print(f"Unique crypto libraries found: {len(metadata['crypto_libraries_found'])}")
        print()
        

        print("ANALYSIS BY PROGRAMMING LANGUAGE:")
        print("-" * 45)
        for lang, summary in self.results['summary_by_language'].items():
            pqc_pct = (summary['pqc_ready_count'] / max(1, len(summary['libraries_used']))) * 100
            print(f"{lang.upper():<15} Files: {summary['files_count']:>4} | "
                  f"Crypto: {summary['crypto_files_count']:>3} | "
                  f"Libraries: {len(summary['libraries_used']):>2} | "
                  f"PQC Ready: {pqc_pct:4.1f}%")
                  

        if self.results['crypto_usage']:
            print()
            print("CRYPTOGRAPHIC LIBRARIES DETECTED:")
            print("-" * 40)
            

            library_counts = Counter()
            for finding in self.results['crypto_usage'] + self.results['package_dependencies']:
                library_counts[finding['library_base']] += 1
                
            for library, count in library_counts.most_common(15):
                print(f"  {library:<25} ({count:>2} occurrences)")
                

        security = self.results['security_analysis']
        if security['high_risk_files'] or security['non_pqc_ready']:
            print()
            print("SECURITY ANALYSIS:")
            print("-" * 20)
            
            if security['high_risk_files']:
                print(f"High risk files: {len(security['high_risk_files'])}")
                
            non_pqc_count = len(security['non_pqc_ready'])
            total_findings = len(self.results['crypto_usage']) + len(self.results['package_dependencies'])
            if non_pqc_count > 0:
                pqc_pct = ((total_findings - non_pqc_count) / total_findings) * 100
                print(f"Post-quantum ready: {pqc_pct:.1f}% ({total_findings - non_pqc_count}/{total_findings})")

    def export_results(self, output_file: str) -> None:
        """Export results to JSON file."""

        export_data = {}
        
        for key, value in self.results.items():
            if key == 'scan_metadata':
                export_data[key] = {
                    k: (list(v) if isinstance(v, set) else v) 
                    for k, v in value.items()
                }
            elif key == 'summary_by_language':
                export_data[key] = {
                    lang: {
                        k: (list(v) if isinstance(v, set) else 
                            dict(v) if isinstance(v, Counter) else v)
                        for k, v in summary.items()
                    }
                    for lang, summary in value.items()
                }
            else:
                export_data[key] = value
                
        try:
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            print(f"\nResults exported to: {output_file}")
        except Exception as e:
            print(f"Error exporting results: {e}")


def main():
    """Main function for command-line usage."""
    parser = argparse.ArgumentParser(
        description="Analyze source code for cryptographic library usage across multiple programming languages",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyzeSourcePackages.py /path/to/project
  python analyzeSourcePackages.py . --output crypto_analysis.json
  python analyzeSourcePackages.py ~/projects --recursive --quiet
        """
    )
    
    parser.add_argument(
        'directory',
        help='Directory to scan for source code files'
    )
    parser.add_argument(
        '--output', '-o',
        help='Export results to JSON file'
    )
    parser.add_argument(
        '--recursive', '-r',
        action='store_true',
        default=True,
        help='Recursively scan subdirectories (default: True)'
    )
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress detailed output'
    )
    
    args = parser.parse_args()
    
    analyzer = SourceCodeAnalyzer()
    
    try:
        analyzer.scan_directory(args.directory, args.recursive)
        
        if not args.quiet:
            analyzer.print_summary()
            
        if args.output:
            analyzer.export_results(args.output)
            

        findings_count = len(analyzer.results['crypto_usage']) + len(analyzer.results['package_dependencies'])
        if findings_count > 0:
            non_pqc = len(analyzer.results['security_analysis']['non_pqc_ready'])
            if non_pqc > findings_count * 0.5:
                print(f"\nWarning: {non_pqc} cryptographic dependencies are not post-quantum ready")
                
    except Exception as e:
        print(f"Error: {e}")
        return 1
        
    return 0


if __name__ == "__main__":
    exit(main())