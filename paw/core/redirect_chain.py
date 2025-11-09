# redirect_chain.py - HTTP Redirect Chain Analysis
import requests
import logging
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urljoin
import time
import re
from collections import defaultdict

logger = logging.getLogger(__name__)

class RedirectChainAnalyzer:
    """Analyze HTTP redirect chains for attribution patterns"""

    def __init__(self, timeout: int = 30, max_redirects: int = 10, verify_ssl: bool = True):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.session = requests.Session()
        # SSL verification configurable via environment or parameter
        import os
        self.verify_ssl = verify_ssl if verify_ssl is not None else os.getenv('PAW_VERIFY_SSL', 'true').lower() == 'true'
        self.session.verify = self.verify_ssl
        if not self.verify_ssl:
            logger.warning("SSL verification is DISABLED - only use for controlled analysis environments")
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def analyze_redirect_chain(self, url: str, headers: Dict[str, str] = None) -> Dict[str, Any]:
        """Analyze complete redirect chain from initial URL"""
        result = {
            'initial_url': url,
            'final_url': url,
            'chain': [],
            'timing': {},
            'utm_parameters': {},
            'redirect_patterns': {},
            'suspicious_indicators': [],
            'attribution_hints': {},
            'errors': []
        }

        try:
            # Prepare headers
            default_headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            if headers:
                default_headers.update(headers)

            start_time = time.time()

            # Follow redirects manually to capture all details
            current_url = url
            redirect_count = 0
            visited_urls = set()

            while redirect_count < self.max_redirects:
                if current_url in visited_urls:
                    result['suspicious_indicators'].append('redirect_loop_detected')
                    break

                visited_urls.add(current_url)
                step_start = time.time()

                try:
                    # Make request with redirect disabled
                    response = self.session.get(
                        current_url,
                        headers=default_headers,
                        timeout=self.timeout,
                        allow_redirects=False
                    )

                    step_time = time.time() - step_start

                    # Record this step
                    step_info = {
                        'url': current_url,
                        'status_code': response.status_code,
                        'response_time': step_time,
                        'headers': dict(response.headers),
                        'redirect_location': response.headers.get('Location'),
                        'server': response.headers.get('Server'),
                        'content_type': response.headers.get('Content-Type'),
                        'content_length': response.headers.get('Content-Length')
                    }

                    result['chain'].append(step_info)

                    # Check for redirect
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location')
                        if location:
                            # Handle relative URLs
                            if not location.startswith(('http://', 'https://')):
                                parsed = urlparse(current_url)
                                base_url = f"{parsed.scheme}://{parsed.netloc}"
                                location = urljoin(base_url, location)

                            current_url = location
                            redirect_count += 1
                        else:
                            break
                    else:
                        # Final destination reached
                        result['final_url'] = current_url
                        break

                except requests.exceptions.RequestException as e:
                    result['errors'].append(f"Request failed for {current_url}: {str(e)}")
                    break

            total_time = time.time() - start_time
            result['timing'] = {
                'total_time': total_time,
                'steps': len(result['chain']),
                'average_step_time': total_time / len(result['chain']) if result['chain'] else 0
            }

            # Analyze the chain
            self._analyze_chain_patterns(result)

        except Exception as e:
            result['errors'].append(f"Chain analysis failed: {str(e)}")
            logger.error(f"Redirect chain analysis failed for {url}: {e}")

        return result

    def _analyze_chain_patterns(self, result: Dict[str, Any]) -> None:
        """Analyze patterns in the redirect chain"""
        chain = result['chain']
        if not chain:
            return

        # Extract UTM parameters
        utm_params = defaultdict(list)
        for step in chain:
            parsed = urlparse(step['url'])
            query_params = parse_qs(parsed.query)

            for param in ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content']:
                if param in query_params:
                    utm_params[param].extend(query_params[param])

        result['utm_parameters'] = dict(utm_params)

        # Detect suspicious patterns
        suspicious = []

        # Check for excessive redirects
        if len(chain) > 5:
            suspicious.append('excessive_redirects')

        # Check for redirect to suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club']
        final_url = result.get('final_url', '')
        if any(final_url.endswith(tld) for tld in suspicious_tlds):
            suspicious.append('suspicious_tld')

        # Check for URL shorteners
        shortener_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'buff.ly']
        for step in chain:
            parsed = urlparse(step['url'])
            if parsed.netloc in shortener_domains:
                suspicious.append('url_shortener_used')
                break

        # Check for tracking pixels or analytics
        tracking_indicators = ['google-analytics.com', 'googletagmanager.com', 'facebook.com/tr',
                             'doubleclick.net', 'googlesyndication.com']
        for step in chain:
            url_str = step['url'].lower()
            if any(indicator in url_str for indicator in tracking_indicators):
                suspicious.append('tracking_pixel_detected')
                break

        result['suspicious_indicators'] = suspicious

        # Generate attribution hints
        hints = {}

        # Domain analysis
        domains = []
        for step in chain:
            parsed = urlparse(step['url'])
            if parsed.netloc:
                domains.append(parsed.netloc)

        if domains:
            hints['domain_chain'] = domains
            hints['unique_domains'] = len(set(domains))

            # Check for domain similarity (potential typosquatting)
            if len(set(domains)) > 1:
                hints['domain_similarity'] = self._check_domain_similarity(domains)

        # Geographic hints from TLD
        final_domain = domains[-1] if domains else ''
        if final_domain:
            tld_hints = self._analyze_tld_geography(final_domain)
            if tld_hints:
                hints['geographic_hints'] = tld_hints

        # Campaign analysis
        if utm_params:
            campaign_info = self._analyze_campaign_parameters(utm_params)
            hints['campaign_analysis'] = campaign_info

        result['attribution_hints'] = hints

    def _check_domain_similarity(self, domains: List[str]) -> List[Dict[str, Any]]:
        """Check for domain similarity patterns"""
        similarities = []

        for i, domain1 in enumerate(domains):
            for j, domain2 in enumerate(domains):
                if i != j:
                    similarity = self._calculate_domain_similarity(domain1, domain2)
                    if similarity > 0.8:  # High similarity threshold
                        similarities.append({
                            'domain1': domain1,
                            'domain2': domain2,
                            'similarity_score': similarity,
                            'type': 'typosquatting_suspicious'
                        })

        return similarities

    def _calculate_domain_similarity(self, domain1: str, domain2: str) -> float:
        """Calculate similarity between two domains"""
        # Simple Levenshtein distance ratio
        def levenshtein_distance(s1, s2):
            if len(s1) < len(s2):
                return levenshtein_distance(s2, s1)
            if len(s2) == 0:
                return len(s1)

            previous_row = list(range(len(s2) + 1))
            for i, c1 in enumerate(s1):
                current_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row

            return previous_row[-1]

        max_len = max(len(domain1), len(domain2))
        if max_len == 0:
            return 1.0

        distance = levenshtein_distance(domain1.lower(), domain2.lower())
        return 1 - (distance / max_len)

    def _analyze_tld_geography(self, domain: str) -> Dict[str, Any]:
        """Analyze geographic hints from TLD"""
        tld_geography = {
            '.ru': 'Russia',
            '.cn': 'China',
            '.in': 'India',
            '.br': 'Brazil',
            '.mx': 'Mexico',
            '.ng': 'Nigeria',
            '.za': 'South Africa',
            '.pl': 'Poland',
            '.tr': 'Turkey',
            '.ir': 'Iran',
            '.kr': 'South Korea',
            '.jp': 'Japan',
            '.de': 'Germany',
            '.fr': 'France',
            '.it': 'Italy',
            '.es': 'Spain',
            '.nl': 'Netherlands',
            '.se': 'Sweden',
            '.no': 'NO',
            '.fi': 'Finland',
            '.dk': 'Denmark'
        }

        parsed = urlparse(f"https://{domain}")
        tld = '.' + parsed.netloc.split('.')[-1] if '.' in parsed.netloc else ''

        if tld in tld_geography:
            return {
                'tld': tld,
                'country': tld_geography[tld],
                'confidence': 'medium'
            }

        return {}

    def _analyze_campaign_parameters(self, utm_params: Dict[str, List[str]]) -> Dict[str, Any]:
        """Analyze UTM campaign parameters for attribution"""
        analysis = {
            'sources': [],
            'mediums': [],
            'campaigns': [],
            'insights': []
        }

        # Extract unique values
        analysis['sources'] = list(set(utm_params.get('utm_source', [])))
        analysis['mediums'] = list(set(utm_params.get('utm_medium', [])))
        analysis['campaigns'] = list(set(utm_params.get('utm_campaign', [])))

        # Generate insights
        insights = []

        # Check for email campaigns
        if any(medium.lower() in ['email', 'mail'] for medium in analysis['mediums']):
            insights.append('email_campaign_detected')

        # Check for social media
        social_sources = ['facebook', 'twitter', 'linkedin', 'instagram', 'tiktok', 'youtube']
        if any(source.lower() in social_sources for source in analysis['sources']):
            insights.append('social_media_campaign')

        # Check for paid advertising
        paid_indicators = ['cpc', 'ppc', 'paid', 'ads', 'adwords', 'googleads']
        if any(medium.lower() in paid_indicators for medium in analysis['mediums']):
            insights.append('paid_advertising')

        analysis['insights'] = insights

        return analysis

    def extract_redirect_patterns(self, chains: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract common patterns from multiple redirect chains"""
        patterns = {
            'common_redirectors': defaultdict(int),
            'common_destinations': defaultdict(int),
            'average_chain_length': 0,
            'suspicious_patterns': [],
            'geographic_distribution': defaultdict(int)
        }

        total_chains = len(chains)
        total_length = 0

        for chain_data in chains:
            chain = chain_data.get('chain', [])
            total_length += len(chain)

            # Count redirectors
            for step in chain[:-1]:  # All except final destination
                parsed = urlparse(step['url'])
                if parsed.netloc:
                    patterns['common_redirectors'][parsed.netloc] += 1

            # Count destinations
            if chain:
                final_step = chain[-1]
                parsed = urlparse(final_step['url'])
                if parsed.netloc:
                    patterns['common_destinations'][parsed.netloc] += 1

            # Geographic analysis
            hints = chain_data.get('attribution_hints', {})
            geo_hints = hints.get('geographic_hints', {})
            if geo_hints.get('country'):
                patterns['geographic_distribution'][geo_hints['country']] += 1

        patterns['average_chain_length'] = total_length / total_chains if total_chains > 0 else 0

        # Find suspicious patterns
        suspicious = []
        for redirector, count in patterns['common_redirectors'].items():
            if count > total_chains * 0.5:  # Used in more than 50% of chains
                suspicious.append(f"Common redirector: {redirector} ({count}/{total_chains})")

        patterns['suspicious_patterns'] = suspicious

        return patterns

def analyze_redirect_chain(url: str, headers: Dict[str, str] = None) -> Dict[str, Any]:
    """Convenience function for redirect chain analysis"""
    analyzer = RedirectChainAnalyzer()
    return analyzer.analyze_redirect_chain(url, headers)