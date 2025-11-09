import socket
import requests
from typing import Dict, List

class InfrastructureMapper:
    """Mappa avanzata dell'infrastruttura criminale"""
    
    def __init__(self):
        self.session = requests.Session()
    
    def comprehensive_map(self, domain: str, ips: List[str]) -> Dict:
        """Mappa completa dell'infrastruttura"""
        try:
            # Validate inputs
            if not ips or not isinstance(ips, list):
                return {
                    'status': 'error',
                    'message': 'Invalid or empty IP list provided',
                    'network_analysis': {},
                    'service_detection': {},
                    'cdn_detection': False,
                    'infrastructure_timeline': []
                }
            
            if not domain or not isinstance(domain, str):
                return {
                    'status': 'error',
                    'message': 'Invalid domain provided',
                    'network_analysis': {},
                    'service_detection': {},
                    'cdn_detection': False,
                    'infrastructure_timeline': []
                }
            
            return {
                'network_analysis': self._analyze_network(ips),
                'service_detection': self._detect_services(ips),
                'cdn_detection': self._detect_cdn(domain, ips),
                'infrastructure_timeline': self._build_timeline(domain)
            }
        except IndexError as e:
            print(f"[infrastructure_mapper] IndexError in comprehensive_map: {e}")
            return {
                'status': 'error',
                'message': f'Index error during mapping: {str(e)}',
                'network_analysis': {},
                'service_detection': {},
                'cdn_detection': False,
                'infrastructure_timeline': []
            }
        except Exception as e:
            print(f"[infrastructure_mapper] Unexpected error in comprehensive_map: {e}")
            return {
                'status': 'error',
                'message': f'Error during comprehensive mapping: {str(e)}',
                'network_analysis': {},
                'service_detection': {},
                'cdn_detection': False,
                'infrastructure_timeline': []
            }
    
    def _analyze_network(self, ips: List[str]) -> Dict:
        """Analisi della rete criminale"""
        if not ips:
            return {}
        
        network_data = {}
        for ip in ips:
            try:
                # WHOIS information
                whois_data = self._get_whois_info(ip)
                # Port scanning (limitato)
                open_ports = self._quick_port_scan(ip)
                
                network_data[ip] = {
                    'whois': whois_data,
                    'open_ports': open_ports,
                    'network_range': self._find_network_range(ip)
                }
            except Exception as e:
                print(f"[infrastructure_mapper] Error analyzing network for {ip}: {e}")
                network_data[ip] = {
                    'whois': {'error': str(e)},
                    'open_ports': [],
                    'network_range': self._find_network_range(ip)
                }
        return network_data
    
    def _detect_services(self, ips: List[str]) -> Dict:
        """Rileva servizi in esecuzione"""
        if not ips:
            return {}
        
        common_ports = [80, 443, 21, 22, 25, 53, 110, 143, 993, 995]
        services = {}
        
        for ip in ips:
            try:
                services[ip] = []
                for port in common_ports:
                    try:
                        if self._check_port(ip, port):
                            service = self._identify_service(ip, port)
                            services[ip].append({
                                'port': port,
                                'service': service,
                                'banner': self._get_banner(ip, port)
                            })
                    except Exception as e:
                        print(f"[infrastructure_mapper] Error detecting service on {ip}:{port}: {e}")
                        continue
            except Exception as e:
                print(f"[infrastructure_mapper] Error detecting services for {ip}: {e}")
                services[ip] = []
        
        return services
    
    def _detect_cdn(self, domain: str, ips: List[str]) -> bool:
        """Rileva se sta usando CDN (Cloudflare, Akamai, etc.)"""
        if not ips or not domain:
            return False
        
        cdn_ips = [
            '104.16.0.0/12',  # Cloudflare
            '173.245.48.0/20', # Cloudflare
            '188.114.96.0/20', # Cloudflare
            '131.0.72.0/22',   # Akamai
            '184.24.0.0/13'    # Akamai
        ]
        
        try:
            for ip in ips:
                for cdn_range in cdn_ips:
                    if self._ip_in_range(ip, cdn_range):
                        return True
        except Exception as e:
            print(f"[infrastructure_mapper] Error detecting CDN: {e}")
        
        return False
    
    def _build_timeline(self, domain: str) -> List[Dict]:
        """Build real infrastructure timeline from multiple sources"""
        if not domain:
            return []
        
        timeline = []
        
        try:
            # 1. Get domain registration date from WHOIS
            whois_data = self._get_whois_info(domain)
            if whois_data and whois_data.get('creation_date'):
                timeline.append({
                    'date': whois_data['creation_date'],
                    'event': 'Domain registered',
                    'source': 'WHOIS'
                })

            # 2. Get SSL certificate history from Certificate Transparency logs
            ct_events = self._query_certificate_transparency(domain)
            if ct_events and isinstance(ct_events, list):
                timeline.extend(ct_events)

            # 3. Add current analysis timestamp
            from datetime import datetime
            timeline.append({
                'date': datetime.now().isoformat(),
                'event': 'Infrastructure analysis performed',
                'source': 'PAW Analysis'
            })

            # Sort by date (safely)
            if timeline:
                timeline.sort(key=lambda x: x.get('date', ''), reverse=False)
        
        except Exception as e:
            print(f"[infrastructure_mapper] Error building timeline for {domain}: {e}")
            timeline = [{
                'date': 'Unknown',
                'event': f'Timeline build failed: {str(e)}',
                'source': 'Error'
            }]

        return timeline

    def _query_certificate_transparency(self, domain: str) -> List[Dict]:
        """Query Certificate Transparency logs for SSL certificate history"""
        try:
            import requests
            import json

            # Use crt.sh API (public CT log aggregator)
            url = f"https://crt.sh/?q={domain}&output=json"

            response = requests.get(url, timeout=10)
            if response.status_code != 200:
                return []

            certs = response.json()
            if not certs or not isinstance(certs, list):
                return []
            
            events = []

            # Process certificate data
            seen_dates = set()
            for cert in certs[:10]:  # Limit to 10 most recent
                try:
                    entry_timestamp = cert.get('entry_timestamp') if isinstance(cert, dict) else None
                    if entry_timestamp and entry_timestamp not in seen_dates:
                        seen_dates.add(entry_timestamp)
                        events.append({
                            'date': entry_timestamp,
                            'event': f"SSL certificate issued (Issuer: {cert.get('issuer_name', 'Unknown')})",
                            'source': 'Certificate Transparency',
                            'common_name': cert.get('common_name', domain),
                            'serial_number': cert.get('serial_number', 'Unknown')
                        })
                except (KeyError, TypeError, IndexError) as e:
                    print(f"[infrastructure_mapper] Error processing cert entry: {e}")
                    continue

            return events

        except ImportError:
            # requests not available
            return []
        except Exception as e:
            print(f"[infrastructure_mapper] Error querying Certificate Transparency: {e}")
            return []
    
    def _get_whois_info(self, ip: str) -> Dict:
        """Real WHOIS lookup for IP address"""
        try:
            import whois
            w = whois.whois(ip)

            return {
                'registrar': w.registrar if hasattr(w, 'registrar') else None,
                'organization': w.org if hasattr(w, 'org') else None,
                'creation_date': str(w.creation_date) if hasattr(w, 'creation_date') else None,
                'expiration_date': str(w.expiration_date) if hasattr(w, 'expiration_date') else None,
                'updated_date': str(w.updated_date) if hasattr(w, 'updated_date') else None,
                'name_servers': w.name_servers if hasattr(w, 'name_servers') else [],
                'emails': w.emails if hasattr(w, 'emails') else [],
                'address': w.address if hasattr(w, 'address') else None,
                'city': w.city if hasattr(w, 'city') else None,
                'state': w.state if hasattr(w, 'state') else None,
                'country': w.country if hasattr(w, 'country') else None,
            }
        except ImportError:
            # Fallback to raw socket WHOIS
            return self._get_whois_info_raw(ip)
        except Exception as e:
            return {'error': str(e), 'status': 'failed'}

    def _get_whois_info_raw(self, ip: str) -> Dict:
        """Fallback raw WHOIS via socket"""
        try:
            import socket
            whois_server = 'whois.iana.org'

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(10)
                sock.connect((whois_server, 43))
                sock.send(f"{ip}\r\n".encode())

                response = b''
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk

                text = response.decode('utf-8', errors='ignore')

                # Parse key fields
                parsed = {'raw': text}
                for line in text.splitlines():
                    if ':' in line:
                        key, value = line.split(':', 1)
                        key = key.strip().lower().replace(' ', '_')
                        value = value.strip()
                        if key in ['organization', 'org', 'country', 'netname', 'abuse']:
                            parsed[key] = value

                return parsed
        except Exception as e:
            return {'error': str(e), 'status': 'failed'}
    
    def _quick_port_scan(self, ip: str) -> List[int]:
        """Scansione porte veloce"""
        open_ports = []
        ports_to_check = [80, 443, 21, 22, 25]
        
        for port in ports_to_check:
            if self._check_port(ip, port):
                open_ports.append(port)
        
        return open_ports
    
    def _check_port(self, ip: str, port: int, timeout: float = 2.0) -> bool:
        """Controlla se una porta è aperta"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                return result == 0
        except:
            return False
    
    def _identify_service(self, ip: str, port: int) -> str:
        """Identifica servizio sulla porta"""
        service_map = {
            80: 'HTTP',
            443: 'HTTPS', 
            21: 'FTP',
            22: 'SSH',
            25: 'SMTP',
            53: 'DNS'
        }
        return service_map.get(port, 'Unknown')
    
    def _get_banner(self, ip: str, port: int) -> str:
        """Prova a ottenere banner del servizio"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(3)
                sock.connect((ip, port))
                if port in [80, 443]:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                return banner[:500]  # Limita lunghezza
        except:
            return "No banner"
    
    def _find_network_range(self, ip: str) -> str:
        """Stima il range di rete per IPv4 e IPv6"""
        try:
            if ':' in ip:  # IPv6
                # Per IPv6, restituisci il /48 (primi 3 gruppi)
                parts = ip.split(':')
                if len(parts) >= 3:
                    return f"{parts[0]}:{parts[1]}:{parts[2]}::/48"
                else:
                    return f"{ip}/128"  # Indirizzo singolo
            else:  # IPv4
                parts = ip.split('.')
                if len(parts) >= 3:
                    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                else:
                    return f"{ip}/32"  # Indirizzo singolo
        except (IndexError, ValueError) as e:
            print(f"[infrastructure_mapper] Error finding network range for {ip}: {e}")
            return f"{ip}/32"  # Fallback sicuro
    
    def _ip_in_range(self, ip: str, ip_range: str) -> bool:
        """Controlla se IP è in un range specifico (supporta IPv4 e IPv6)"""
        try:
            if ':' in ip:  # IPv6
                # Per IPv6, controllo semplice basato sui primi gruppi
                if '/' in ip_range:
                    base_ip = ip_range.split('/')[0]
                    base_parts = base_ip.split(':')[:3]  # Primi 3 gruppi
                    ip_parts = ip.split(':')[:3]
                    return base_parts == ip_parts
                return False
            else:  # IPv4
                # Implementazione semplificata per IPv4
                if '/' in ip_range:
                    base_ip = ip_range.split('/')[0]
                    return ip.startswith('.'.join(base_ip.split('.')[:2]))
                return False
        except (IndexError, ValueError) as e:
            print(f"[infrastructure_mapper] Error checking IP range for {ip}: {e}")
            return False
