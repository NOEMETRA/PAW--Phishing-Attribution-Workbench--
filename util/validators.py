"""Unused legacy validation helpers; no supported operational entry point.

These algorithms are unvalidated and are not PAW admission or containment.
No tracked production consumer was identified. Retained for inspection only;
see docs/legacy-conclusion-publication.md.
"""

import os
import re
from urllib.parse import urlparse
from typing import Optional


class ValidationError(Exception):
    """Raised when input validation fails"""
    pass


class InputValidator:
    """Centralized input validation for PAW"""

    @staticmethod
    def validate_url(url: str, allow_http: bool = True, require_tld: bool = True) -> str:
        """
        Validate and sanitize URL

        Args:
            url: URL to validate
            allow_http: Allow HTTP scheme (default: True)
            require_tld: Require top-level domain (default: True)

        Returns:
            Validated URL

        Raises:
            ValidationError: If URL is invalid
        """
        if not isinstance(url, str):
            raise ValidationError("URL must be a string")

        url = url.strip()
        if not url:
            raise ValidationError("URL cannot be empty")

        try:
            parsed = urlparse(url)
        except Exception as e:
            raise ValidationError(f"Failed to parse URL: {e}")

        # Check scheme
        allowed_schemes = ['https', 'http'] if allow_http else ['https']
        if parsed.scheme not in allowed_schemes:
            raise ValidationError(f"Invalid URL scheme: {parsed.scheme}. Allowed: {', '.join(allowed_schemes)}")

        # Check hostname
        if not parsed.netloc:
            raise ValidationError("URL must have a hostname")

        # Check for TLD if required
        if require_tld and '.' not in parsed.netloc:
            raise ValidationError("URL must have a top-level domain")

        return url

    @staticmethod
    def validate_domain(domain: str, allow_wildcards: bool = False) -> str:
        """
        Validate domain name

        Args:
            domain: Domain to validate
            allow_wildcards: Allow wildcard domains (*.example.com)

        Returns:
            Validated domain

        Raises:
            ValidationError: If domain is invalid
        """
        if not isinstance(domain, str):
            raise ValidationError("Domain must be a string")

        domain = domain.strip().lower()
        if not domain:
            raise ValidationError("Domain cannot be empty")

        # Handle wildcards
        if domain.startswith('*.'):
            if not allow_wildcards:
                raise ValidationError("Wildcard domains not allowed")
            domain_to_check = domain[2:]
        else:
            domain_to_check = domain

        # Domain pattern: alphanumeric + hyphens, must have TLD
        pattern = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
        if not re.match(pattern, domain_to_check):
            raise ValidationError(f"Invalid domain format: {domain}")

        # Additional checks
        if len(domain) > 253:
            raise ValidationError("Domain too long (max 253 characters)")

        labels = domain_to_check.split('.')
        for label in labels:
            if len(label) > 63:
                raise ValidationError(f"Domain label too long: {label} (max 63 characters)")
            if label.startswith('-') or label.endswith('-'):
                raise ValidationError(f"Domain label cannot start/end with hyphen: {label}")

        return domain

    @staticmethod
    def validate_ip(ip: str, allow_private: bool = True) -> str:
        """
        Validate IP address (IPv4 or IPv6)

        Args:
            ip: IP address to validate
            allow_private: Allow private IP ranges

        Returns:
            Validated IP address

        Raises:
            ValidationError: If IP is invalid
        """
        if not isinstance(ip, str):
            raise ValidationError("IP address must be a string")

        ip = ip.strip()
        if not ip:
            raise ValidationError("IP address cannot be empty")

        # Try IPv4
        ipv4_pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
        match = re.match(ipv4_pattern, ip)
        if match:
            octets = [int(g) for g in match.groups()]
            for octet in octets:
                if octet > 255:
                    raise ValidationError(f"Invalid IPv4 address: {ip} (octet > 255)")

            # Check for private ranges if not allowed
            if not allow_private:
                first_octet = octets[0]
                second_octet = octets[1]
                if (first_octet == 10 or
                    (first_octet == 172 and 16 <= second_octet <= 31) or
                    (first_octet == 192 and second_octet == 168)):
                    raise ValidationError(f"Private IP address not allowed: {ip}")

            return ip

        # Try IPv6 (basic validation)
        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$'
        if re.match(ipv6_pattern, ip):
            return ip

        # Try compressed IPv6
        if '::' in ip:
            parts = ip.split('::')
            if len(parts) == 2:
                return ip

        raise ValidationError(f"Invalid IP address format: {ip}")

    @staticmethod
    def validate_email(email: str) -> str:
        """
        Validate email address

        Args:
            email: Email to validate

        Returns:
            Validated email

        Raises:
            ValidationError: If email is invalid
        """
        if not isinstance(email, str):
            raise ValidationError("Email must be a string")

        email = email.strip().lower()
        if not email:
            raise ValidationError("Email cannot be empty")

        # Basic email pattern
        pattern = r'^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$'
        if not re.match(pattern, email):
            raise ValidationError(f"Invalid email format: {email}")

        if len(email) > 254:
            raise ValidationError("Email too long (max 254 characters)")

        local, domain = email.split('@')
        if len(local) > 64:
            raise ValidationError("Email local part too long (max 64 characters)")

        return email

    @staticmethod
    def sanitize_filename(filename: str, max_length: int = 255) -> str:
        """
        Sanitize filename to prevent path traversal

        Args:
            filename: Filename to sanitize
            max_length: Maximum filename length

        Returns:
            Sanitized filename

        Raises:
            ValidationError: If filename is invalid
        """
        if not isinstance(filename, str):
            raise ValidationError("Filename must be a string")

        # Extract basename to prevent path traversal
        filename = os.path.basename(filename)

        if not filename:
            raise ValidationError("Filename cannot be empty")

        # Check for path traversal attempts
        if '..' in filename:
            raise ValidationError("Path traversal detected in filename")

        # Check for null bytes
        if '\x00' in filename:
            raise ValidationError("Null byte detected in filename")

        # Remove dangerous characters
        dangerous_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
        for char in dangerous_chars:
            if char in filename:
                raise ValidationError(f"Dangerous character in filename: {char}")

        if len(filename) > max_length:
            raise ValidationError(f"Filename too long (max {max_length} characters)")

        return filename

    @staticmethod
    def validate_path(path: str, must_exist: bool = False, base_path: Optional[str] = None) -> str:
        """
        Validate file/directory path

        Args:
            path: Path to validate
            must_exist: Path must exist on filesystem
            base_path: Path must be within this base directory

        Returns:
            Validated absolute path

        Raises:
            ValidationError: If path is invalid
        """
        if not isinstance(path, str):
            raise ValidationError("Path must be a string")

        path = path.strip()
        if not path:
            raise ValidationError("Path cannot be empty")

        # Check for null bytes
        if '\x00' in path:
            raise ValidationError("Null byte detected in path")

        # Get absolute path
        try:
            abs_path = os.path.abspath(path)
        except Exception as e:
            raise ValidationError(f"Failed to resolve path: {e}")

        # Check if path exists
        if must_exist and not os.path.exists(abs_path):
            raise ValidationError(f"Path does not exist: {path}")

        # Check if within base path (prevent path traversal)
        if base_path:
            base_abs = os.path.abspath(base_path)
            if not abs_path.startswith(base_abs):
                raise ValidationError(f"Path outside allowed directory: {path}")

        return abs_path

    @staticmethod
    def validate_port(port: int, allow_privileged: bool = False) -> int:
        """
        Validate network port number

        Args:
            port: Port number to validate
            allow_privileged: Allow privileged ports (1-1023)

        Returns:
            Validated port number

        Raises:
            ValidationError: If port is invalid
        """
        if not isinstance(port, int):
            try:
                port = int(port)
            except (ValueError, TypeError):
                raise ValidationError("Port must be an integer")

        if port < 1 or port > 65535:
            raise ValidationError(f"Port out of range: {port} (must be 1-65535)")

        if not allow_privileged and port < 1024:
            raise ValidationError(f"Privileged port not allowed: {port} (use port >= 1024)")

        return port

    @staticmethod
    def validate_asn(asn: str) -> str:
        """
        Validate Autonomous System Number

        Args:
            asn: ASN to validate (e.g., "AS15169" or "15169")

        Returns:
            Validated ASN in AS##### format

        Raises:
            ValidationError: If ASN is invalid
        """
        if not isinstance(asn, str):
            raise ValidationError("ASN must be a string")

        asn = asn.strip().upper()
        if not asn:
            raise ValidationError("ASN cannot be empty")

        # Remove AS prefix if present
        if asn.startswith('AS'):
            asn_number = asn[2:]
        else:
            asn_number = asn

        # Validate number
        if not asn_number.isdigit():
            raise ValidationError(f"Invalid ASN format: {asn}")

        asn_int = int(asn_number)
        if asn_int < 1 or asn_int > 4294967295:
            raise ValidationError(f"ASN out of range: {asn_int}")

        return f"AS{asn_number}"

    @staticmethod
    def validate_hash(hash_value: str, hash_type: Optional[str] = None) -> str:
        """
        Validate cryptographic hash

        Args:
            hash_value: Hash to validate
            hash_type: Expected hash type (md5, sha1, sha256, sha512)

        Returns:
            Validated hash (lowercase)

        Raises:
            ValidationError: If hash is invalid
        """
        if not isinstance(hash_value, str):
            raise ValidationError("Hash must be a string")

        hash_value = hash_value.strip().lower()
        if not hash_value:
            raise ValidationError("Hash cannot be empty")

        # Check if hex
        if not re.match(r'^[0-9a-f]+$', hash_value):
            raise ValidationError(f"Hash must be hexadecimal: {hash_value}")

        # Validate length based on type
        expected_lengths = {
            'md5': 32,
            'sha1': 40,
            'sha256': 64,
            'sha512': 128
        }

        if hash_type:
            hash_type = hash_type.lower()
            if hash_type not in expected_lengths:
                raise ValidationError(f"Unknown hash type: {hash_type}")

            expected_len = expected_lengths[hash_type]
            if len(hash_value) != expected_len:
                raise ValidationError(f"Invalid {hash_type} length: {len(hash_value)} (expected {expected_len})")
        else:
            # Auto-detect type
            if len(hash_value) not in expected_lengths.values():
                raise ValidationError(f"Invalid hash length: {len(hash_value)}")

        return hash_value
