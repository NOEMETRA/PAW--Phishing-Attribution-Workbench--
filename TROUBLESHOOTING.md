# PAW Troubleshooting Guide

This guide helps you resolve common issues when using PAW (Phishing Attribution Workbench).

## Common Issues

### "No origin IP found"
**Symptoms**: Analysis shows no transmitting server IP
**Causes**:
- Email was forwarded through multiple internal relays
- Email originated from a cloud service (Office 365, Gmail, etc.)
- Headers were stripped during forwarding

**Solutions**:
```bash
# Use conservative scoring profile
paw analyze email.eml --profile conservative

# Check technical report for header details
cat cases/*/report/technical.md
```

### "API rate limit exceeded"
**Symptoms**: Analysis fails with rate limit errors
**Causes**:
- VirusTotal free tier: 4 requests/minute
- AbuseIPDB rate limiting
- Other threat intelligence API limits

**Solutions**:
```bash
# Wait and retry
sleep 60
paw analyze email.eml

# Skip network intelligence gathering
paw analyze email.eml --no-egress

# Use quick mode (minimal network calls)
paw quick email.eml
```

### "Detonation timeout"
**Symptoms**: URL detonation fails with timeout errors
**Causes**:
- Phishing site is slow or unresponsive
- Network connectivity issues
- Site requires specific user agents or headers

**Solutions**:
```bash
# Increase timeout
paw detonate --case <case_id> --timeout 60

# Skip detonation in analysis
paw analyze email.eml --no-egress
```

### "Permission denied" / "Access denied"
**Symptoms**: Cannot write to cases directory or read input files
**Causes**:
- Insufficient file permissions
- Running in restricted environment
- Antivirus blocking file operations

**Solutions**:
```bash
# Check permissions
ls -la email.eml
ls -ld cases/

# Run with appropriate permissions
sudo paw analyze email.eml

# Use different working directory
cd /tmp
paw analyze /path/to/email.eml
```

### "Module not found" / Import errors
**Symptoms**: Python import errors on startup
**Causes**:
- Missing dependencies
- Virtual environment issues
- Python path problems

**Solutions**:
```bash
# Install dependencies
pip install -r requirements.txt

# Check Python environment
python -c "import rich, requests, dns.resolver"

# Use correct Python interpreter
python3 -m paw analyze email.eml
```

### "No URLs found in email"
**Symptoms**: Analysis shows no URLs to detonate
**Causes**:
- Email uses URL shorteners or redirectors
- URLs are embedded in images or attachments
- Email is text-only phishing

**Solutions**:
```bash
# Observe separately extracted UTF-8 text; preserve the original MIME email
paw deobfuscate --file extracted-utf8.txt

# Manual URL extraction
grep -i "http" email.eml

# Use forensic mode for deeper analysis
paw forensic email.eml
```

### "STIX export fails"
**Symptoms**: Cannot export case in STIX format
**Causes**:
- Missing analysis data
- Corrupted case files
- STIX library issues

**Solutions**:
```bash
# Verify case integrity
paw verify --case <case_id>

# Re-run analysis with STIX export
paw analyze email.eml --stix

# Check STIX file
cat cases/*/report/stix.json | jq .
```

### "Canary server won't start"
Canary deployment is intentionally unavailable. A nonzero exit with
`Canary deployment unavailable` is the expected result, not a port, firewall or
permissions problem. Changing ports or elevating privileges will not enable it.
The old collector appended files to sealed cases and invalidated their inventory.
See [canary status](docs/canary-status.md) for the deferred isolated-lab collector
and separate observation storage requirements.

## Performance Issues

### Analysis is too slow
```bash
# Use quick mode
paw quick email.eml

# Skip network operations
paw analyze email.eml --no-egress

# Use conservative profile
paw analyze email.eml --profile conservative
```

### High memory usage
```bash
# Process one email at a time
paw analyze single.eml

# Close other applications
# Monitor memory: htop or Activity Monitor
```

### Large case directories
```bash
# Clean old cases
find cases/ -type d -mtime +30 -exec rm -rf {} +

# Archive completed cases
paw export --case <case_id> --format zip
```

## Network Issues

### DNS resolution fails
```bash
# Check DNS configuration
cat /etc/resolv.conf

# Use different DNS
echo "nameserver 8.8.8.8" > /etc/resolv.conf

# Skip DNS-dependent features
paw analyze email.eml --no-egress
```

### SSL/TLS errors
```bash
# Update certificates
pip install --upgrade certifi

# Skip SSL verification (not recommended)
export PYTHONHTTPSVERIFY=0

# Use system certificates
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
```

## Data Issues

### Corrupted .eml files
**Symptoms**: Parsing errors, missing headers
**Solutions**:
```bash
# Validate email format
python -c "import email; email.message_from_file(open('email.eml'))"

# Re-export from email client
# Use different export format if available
```

### Missing analysis data
**Symptoms**: Incomplete reports, missing intelligence
**Solutions**:
```bash
# Re-run analysis
paw analyze email.eml --forensic

# Check case directory
ls -la cases/case-*/

# Verify file integrity
paw verify --case <case_id>
```

## Getting Help

### Debug mode
```bash
# Enable verbose logging
paw analyze email.eml --debug

# Check log files
tail -f paw.log
```

### Report issues
- Check existing issues: https://github.com/your-org/paw/issues
- Create new issue with:
  - PAW version: `paw --version`
  - Python version: `python --version`
  - Error messages and traceback
  - Sample email (anonymized)

### Community support
- Documentation: https://paw.readthedocs.io/
- Forum: https://community.paw-project.org/
- Chat: #paw-support on Slack

## Emergency Contacts

For security incidents or urgent issues:
- Security team: security@your-org.com
- Emergency hotline: +1-555-0123
- On-call engineer: pager@your-org.com
