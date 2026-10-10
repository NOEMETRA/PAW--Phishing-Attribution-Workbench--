# PAW - Phishing Attribution Workbench

🐾 **PAW** is a comprehensive tool for analyzing phishing emails and attributing them to threat actors through advanced intelligence gathering and forensic analysis.

## Quick Start (5 minutes)

### 1. Install PAW
```bash
pip install paw-forensics
# or from source
git clone https://github.com/your-org/paw.git
cd paw
pip install -r requirements.txt
```

### 2. Analyze Your First Email
```bash
# Quick analysis (recommended for most users)
paw analyze suspicious.eml

# Fast analysis without network calls
paw quick suspicious.eml

# Complete analysis with all features
paw full suspicious.eml

# Maximum detail forensic analysis
paw forensic suspicious.eml
```

### 3. View Results
PAW creates a case directory with comprehensive reports:
```
cases/case-20251029-abc123/
├── report/
│   ├── executive.md      # Human-readable summary
│   └── technical.md      # Detailed technical analysis
├── evidence/             # Forensic evidence
├── graphs/              # Visual attribution graphs
└── [analysis files]     # JSON data from intelligence modules
```

### 4. Key Findings
After analysis, you'll see a beautiful terminal summary showing:
- **Verdict**: Malicious/Suspicious/Low Risk with confidence score
- **Origin**: IP, ASN, Country of the attacking infrastructure
- **Key Findings**: Criminal infrastructure, TLS fingerprints, etc.
- **Operator Hypothesis**: AI-generated attribution with confidence
- **Next Steps**: Recommended actions

## Analysis Modes

| Command | Purpose | Network | Exports | Speed |
|---------|---------|---------|---------|-------|
| `paw quick` | Fast triage | ❌ | ❌ | ⚡ Fast |
| `paw analyze` | Standard analysis | ⚠️ | Optional | 🔄 Medium |
| `paw full` | Complete analysis | ✅ | ✅ | 🐌 Slow |
| `paw forensic` | Maximum detail | ✅ | ✅ | 🐌 Slowest |

## Common Workflows

### Incident Response
```bash
# 1. Quick triage
paw quick suspicious.eml

# 2. If suspicious, do full analysis
paw full suspicious.eml

# 3. Export for sharing
paw export --case case-20251029-abc123 --format zip
```

### Threat Hunting
```bash
# Analyze multiple emails
paw analyze inbox/ --profile strict

# Search for related cases
paw query --by ip --value 192.168.1.1
```

### Forensic Investigation
```bash
# Maximum detail analysis
paw forensic evidence.eml

# Detonate URLs safely
paw detonate --case case-20251029-abc123

```

Canary deployment is currently unavailable. The legacy collector invalidated
sealed cases by appending new observations. Its CLI and launcher reject startup;
see [canary status](docs/canary-status.md). Collection awaits separate observation
storage in the isolated lab.

## Understanding Results

### Verdict Levels
- **🚨 LIKELY MALICIOUS** (0.8+): High confidence phishing
- **⚠️ SUSPICIOUS** (0.6-0.8): Potential phishing, needs review
- **✅ LOW RISK** (<0.6): Probably legitimate

### Intelligence Modules
PAW integrates multiple intelligence sources:
- **Criminal Hunter**: Identifies known malicious infrastructure
- **Infrastructure Mapper**: Maps attacker network topology
- **Threat Intelligence**: Correlates with global threat feeds
- **SSL Analysis**: Certificate fingerprinting
- **Deobfuscation**: Reveals hidden malicious content

## Next Steps

1. **Read the executive summary**: `cat cases/*/report/executive.md`
2. **Review technical details**: `cat cases/*/report/technical.md`
3. **Submit abuse reports**: Use the generated abuse packages
4. **Export STIX**: `paw export --case <id> --format stix`

## Need Help?

- `paw help` - Show all commands
- `paw help <command>` - Detailed help for specific command
- Check the troubleshooting guide below for common issues
