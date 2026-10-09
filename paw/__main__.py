
import argparse, os, sys, json, shutil
import asyncio, uuid
from pathlib import Path
from .core.runtime import RunLimits, atomic_json, supervise, preserve_interrupted
from .core.verify import verify_case
from .core.exporter import export_case
from .core.scoring import validate_deobfuscation_weight
from .core.process_recovery import process_identity
from .core.runtime import read_progress
from .core.job_registry import require_stopped_case

_analysis_limits = RunLimits()

def trace_sources(src, lang, stix, abuse, anchor, no_egress, profile='default', deob_weight=.30):
    """CLI and API share the same supervised worker and honest terminal states."""
    identifier = 'analysis_'+uuid.uuid4().hex
    control = Path.cwd()/'jobs'/identifier
    control.mkdir(parents=True)
    state = control.parent/(identifier+'.json')
    job = {'origin':'cli','status':'running','no_egress':bool(no_egress),
           'filename':Path(src).name,
           'supervisor_owner':process_identity(os.getpid(),dedicated_group=False)}
    atomic_json(state,job)
    request, result = control/'request.json', control/'result.json'
    atomic_json(request, {'file_path':str(Path(src).resolve()),'lang':lang,'stix':stix,
        'abuse':abuse,'anchor':anchor,'no_egress':no_egress,'profile':profile,'deob_weight':deob_weight})
    env = {'PYTHONPATH':str(Path(__file__).resolve().parents[1]),'PAW_ANALYSIS_ID':identifier}
    try:
        outcome = asyncio.run(supervise([sys.executable,'-X','utf8','-m','paw.web.worker',str(request),str(result)],
            cwd=Path.cwd(), control=control, limits=_analysis_limits, env=env))
        job['supervisor'] = outcome
        with (control/'worker.log').open('rb') as log:
            print(log.read(_analysis_limits.log_bytes).decode('utf-8', errors='replace'))
        if outcome['status'] != 'exited':
            job.update(status=outcome['status'],error=outcome['error'])
            raise RuntimeError(f"{outcome['status']}: {outcome['error']}; logs: {control}")
        value = read_progress(result)
        if outcome['returncode'] or value.get('status') != 'completed':
            raise RuntimeError(value.get('error',f'Worker failed; logs: {control}'))
        job.update(value)
        job['case_id'] = value['case_ids'][0]
        return [str(Path.cwd()/'cases'/case_id) for case_id in value['case_ids']]
    except KeyboardInterrupt:
        job.update(status='cancelled',error='CLI interrupted by operator')
        print(f'Cancelled; evidence and logs preserved in {control}')
        raise
    except Exception as exc:
        if job['status'] == 'running': job['status'] = 'failed'
        job['error'] = str(exc)
        raise
    finally:
        job['supervisor'] = read_progress(control/'supervisor.json')
        if job['status'] != 'completed':
            job['partial_cases'] = preserve_interrupted(Path.cwd(),control,job['status'],job.get('error'))
        atomic_json(state,job)

# Suppress SSL verification warnings for security testing
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass

def handle_error(error_type, message, details=None, suggestions=None):
    """Handle and display errors in a user-friendly way."""
    console = None
    try:
        from rich.console import Console
        from rich.panel import Panel
        console = Console()
    except ImportError:
        console = None

    error_messages = {
        "file_not_found": {
            "title": "❌ File Not Found",
            "message": f"The specified file was not found: {message}",
            "suggestions": [
                "Check if the file path is correct",
                "Ensure the file exists and is readable",
                "Use absolute paths for better reliability"
            ]
        },
        "parse_error": {
            "title": "❌ Email Parsing Failed",
            "message": f"Failed to parse the email file: {message}",
            "suggestions": [
                "Verify the file is a valid .eml format",
                "Check if the file is corrupted",
                "Try re-exporting the email from your client"
            ]
        },
        "network_error": {
            "title": "❌ Network Error",
            "message": f"Network operation failed: {message}",
            "suggestions": [
                "Check your internet connection",
                "Try again later",
                "The --no-egress flag enforces application policy, not an OS sandbox",
                "Use a firewall or isolated VM/network policy to block outbound traffic"
            ]
        },
        "permission_error": {
            "title": "❌ Permission Denied",
            "message": f"Access denied: {message}",
            "suggestions": [
                "Check file permissions",
                "Run with appropriate privileges",
                "Ensure write access to the working directory"
            ]
        },
        "generic": {
            "title": "❌ Error",
            "message": message,
            "suggestions": suggestions or ["Check the error details above", "Try with --debug for more information"]
        }
    }

    error_info = error_messages.get(error_type, error_messages["generic"])

    if console:
        panel = Panel(
            f"{error_info['message']}\n\n"
            f"[bold]Possible causes:[/bold]\n" +
            "\n".join(f"• {s}" for s in error_info.get('suggestions', [])) +
            (f"\n\n[bold]Details:[/bold]\n{details}" if details else ""),
            title=error_info['title'],
            border_style="red"
        )
        console.print(panel)
    else:
        print(f"{error_info['title']}")
        print(f"{error_info['message']}")
        if error_info.get('suggestions'):
            print("\nPossible causes:")
            for s in error_info['suggestions']:
                print(f"• {s}")
        if details:
            print(f"\nDetails: {details}")

    sys.exit(1)

def main():
    global _analysis_limits
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='replace')
    try:
        parser = argparse.ArgumentParser(
            prog="paw",
            description="🐾 PAW - Phishing Attribution Workbench",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  paw analyze email.eml                    # Quick analysis
  paw analyze email.eml --forensic         # Request optional anchoring
  paw analyze email.eml --stix --abuse     # With exports
  paw quick email.eml                      # Fast preset
  paw full email.eml                       # Complete analysis
  paw forensic email.eml                   # Strict profile, exports, optional anchoring

For help: paw help <command>
        """
        )
        sub = parser.add_subparsers(dest="cmd", required=True)

        # ANALYZE command (new main command)
        p_analyze = sub.add_parser("analyze", help="Analyze email(s) and generate attribution report")
        p_analyze.add_argument("email", help="Path to .eml file or directory")
        p_analyze.add_argument("--profile", choices=["default", "strict", "conservative"], default="default",
                              help="Scoring profile")
        p_analyze.add_argument("--stix", action="store_true", help="Request STIX export; conformance currently unavailable")
        p_analyze.add_argument("--abuse", action="store_true", help="Generate abuse package")
        p_analyze.add_argument("--forensic", action="store_true", help="Request optional Rekor anchoring; does not change profile or enable exports")
        p_analyze.add_argument("--no-egress", action="store_true", help="Do not contact suspicious infra")
        p_analyze.add_argument("--lang", default="en", help="Abuse-package language: it or en fallback; main reports remain English")

        # PRESET commands (shortcuts)
        p_quick = sub.add_parser("quick", help="Fast analysis, no egress")
        p_quick.add_argument("email", help="Path to .eml file")

        p_full = sub.add_parser("full", help="Complete analysis with detonation")
        p_full.add_argument("email", help="Path to .eml file")
        p_full.add_argument("--lang", default="en", help="Abuse-package language: it or en fallback; main reports remain English")
        p_full.add_argument("--stix", action="store_true", help="Compatibility flag: STIX is always requested by full; conformance unavailable")
        p_full.add_argument("--abuse", action="store_true", help="Compatibility flag: abuse package is always enabled by full")
        p_full.add_argument("--no-egress", action="store_true", help="Do not contact suspicious infra")

        p_forensic = sub.add_parser("forensic", help="Strict profile + exports + optional anchoring")
        p_forensic.add_argument("email", help="Path to .eml file")
        p_forensic.add_argument("--lang", default="en", help="Abuse-package language: it or en fallback; main reports remain English")
        p_forensic.add_argument("--stix", action="store_true", help="Compatibility flag: STIX is always requested by forensic; conformance unavailable")
        p_forensic.add_argument("--abuse", action="store_true", help="Compatibility flag: abuse package is always enabled by forensic")
        p_forensic.add_argument("--no-egress", action="store_true", help="Do not contact suspicious infra")

        # Legacy TRACE command (keep for compatibility)
        p_trace = sub.add_parser("trace", help="Legacy: use 'analyze' instead")
        p_trace.add_argument("--src", required=True, help="Path to .eml file or directory")
        p_trace.add_argument("--lang", default="en", help="Abuse-package language: it or en fallback; main reports remain English")
        p_trace.add_argument("--stix", action="store_true", help="Request STIX export; conformance currently unavailable")
        p_trace.add_argument("--abuse", action="store_true", help="Generate abuse package")
        p_trace.add_argument("--anchor", action="store_true", help="(Optional) Anchor Merkle root to Rekor")
        p_trace.add_argument("--no-egress", action="store_true", help="Do not contact suspicious infra")
        p_trace.add_argument("--profile", choices=["default", "strict", "conservative"], default="default", help="Scoring profile")
        p_trace.add_argument("--deob-weight", type=validate_deobfuscation_weight, default=0.30, help="Finite deobfuscation weight between 0 and 1")

        # Other commands remain the same
        p_verify = sub.add_parser("verify", help="Verify evidence integrity for a case")
        p_verify.add_argument("--case", required=True, help="Path to case directory")

        p_export = sub.add_parser("export", help="Export case as zip or capsule")
        p_export.add_argument("--case", required=True)
        p_export.add_argument("--format", choices=["zip"], default="zip")

        p_query = sub.add_parser("query", help="Query recent cases by indicator")
        p_query.add_argument("--by", choices=["ip", "domain", "asn", "org"], required=True, help="Query by indicator type")
        p_query.add_argument("--value", required=True, help="Indicator value to search for")
        p_query.add_argument("--days", type=int, default=30, help="Look back days")

        # DETONATE
        p_det = sub.add_parser("detonate", help="Observational detonation of URLs")
        p_det.add_argument("--url", help="Single URL to detonate")
        p_det.add_argument("--case", help="Existing case id (extract URLs from headers)")
        p_det.add_argument("--timeout", type=int, default=35)
        p_det.add_argument("--pcap", action="store_true", help="Capture pcap via tcpdump if available")
        p_det.add_argument("--headless", action="store_true", default=True)
        p_det.add_argument("--observe", action="store_true", default=True, help="Block POST/PUT/PATCH/DELETE")

        # CANARY
        p_can = sub.add_parser("canary", help="Run passive canary server for attribution")
        p_can.add_argument("--case", required=True)
        p_can.add_argument("--port", type=int, default=8787)

        # DEOBFUSCATE
        p_deob = sub.add_parser("deobfuscate", help="Analyze content for obfuscation techniques")
        p_deob.add_argument("--text", help="Text content to analyze")
        p_deob.add_argument("--file", help="File containing content to analyze")
        p_deob.add_argument("--url", help="URL to deobfuscate")
        p_deob.add_argument("--json", action="store_true", help="Output results as JSON")

        # HELP command
        p_help = sub.add_parser("help", help="Show help for commands")
        p_help.add_argument("topic", nargs="?", help="Command to get help for")

        # GUI command
        p_gui = sub.add_parser("gui", help="Launch the local email workbench")
        p_gui.add_argument("--debug", action="store_true", help="Enable debug logging")
        p_gui.add_argument('--port',type=int,default=8765,help='Loopback port')
        p_gui.add_argument('--data-dir',help='Analysis data directory (default: current directory)')
        p_gui.add_argument('--no-browser',action='store_true',help='Start without automatically opening a browser')

        p_update = sub.add_parser("update", help="Update report with detonation/canary data")
        p_update.add_argument("--case", required=True, help="Path to case directory")

        # MONITOR command (Sentinel)
        p_monitor = sub.add_parser("monitor", help="Continuous monitoring of phishing campaigns")
        p_monitor.add_argument("action", choices=["start", "stop", "status", "add", "remove", "list", "check", "files", "integrity"],
                              help="Monitoring action")
        p_monitor.add_argument("--case", help="Case ID to monitor (for add action)")
        p_monitor.add_argument("--url", help="URL to monitor (for add action)")
        p_monitor.add_argument("--campaign", help="Campaign ID (for check action)")

        # GEOGRAPHIC command (Sentinel Intelligence)
        p_geo = sub.add_parser("geographic", aliases=["geo"], help="Generate geographic intelligence reports")
        p_geo.add_argument("action", choices=["report", "stats", "map"], help="Geographic action")
        p_geo.add_argument("--case", help="Case ID to analyze (optional)")
        p_geo.add_argument("--min-confidence", type=float, default=0.0, help="Minimum confidence threshold (0.0-1.0)")
        p_geo.add_argument("--output", choices=["html", "json", "both"], default="both", help="Output format")

        for analysis_parser in (p_analyze, p_quick, p_full, p_forensic, p_trace):
            analysis_parser.add_argument('--deadline', type=float, default=900, help='Overall analysis deadline in seconds')
            analysis_parser.add_argument('--stage-timeout', type=float, default=120, help='Maximum elapsed time per analysis stage')
            analysis_parser.add_argument('--memory-mib', type=int, default=2048, help='Worker memory budget in MiB')
        args = parser.parse_args()
        if args.cmd in {'analyze','quick','full','forensic','trace'}:
            _analysis_limits = RunLimits(wall_seconds=args.deadline, stage_seconds=args.stage_timeout,
                memory_bytes=args.memory_mib * 1024**2)

        # Handle new commands
        if args.cmd == "analyze":
            # Convert analyze to trace call
            if not os.path.exists(args.email):
                handle_error("file_not_found", args.email)
            trace_sources(args.email, args.lang, args.stix, args.abuse,
                         args.forensic,  # Use forensic as anchor
                         args.no_egress, args.profile, 0.30)  # Default deob_weight

        elif args.cmd == "quick":
            # Quick preset: fast, no egress
            if not os.path.exists(args.email):
                handle_error("file_not_found", args.email)
            trace_sources(args.email, "en", False, False, False, True, "default", 0.30)

        elif args.cmd == "full":
            # Full preset: complete with exports
            if not os.path.exists(args.email):
                handle_error("file_not_found", args.email)
            trace_sources(args.email, args.lang, True, True, False, args.no_egress, "strict", 0.30)

        elif args.cmd == "forensic":
            # Forensic preset: maximum detail + anchoring
            if not os.path.exists(args.email):
                handle_error("file_not_found", args.email)
            trace_sources(args.email, args.lang, True, True, True, args.no_egress, "strict", 0.30)

        elif args.cmd == "help":
            if args.topic:
                show_command_help(args.topic)
            else:
                show_main_help()

        elif args.cmd == "gui":
            from .gui.launcher import main
            main(port=args.port,data_dir=args.data_dir,open_browser=not args.no_browser,debug=args.debug)

        # Legacy commands
        elif args.cmd == "trace":
            if not os.path.exists(args.src):
                handle_error("file_not_found", args.src)
            trace_sources(args.src, args.lang, args.stix, args.abuse, args.anchor, args.no_egress, args.profile, args.deob_weight)

        elif args.cmd == "verify":
            require_stopped_case(args.case)
            ok = verify_case(args.case)
            sys.exit(0 if ok else 2)

        elif args.cmd == "export":
            require_stopped_case(args.case)
            export_case(args.case, args.format)

        elif args.cmd == "query":
            from .core.index import query_recent
            results = query_recent(args.by, args.value, args.days)
            print(json.dumps(results, indent=2))

        elif args.cmd == "detonate":
            from .detonate.runner import run_detonation
            run_detonation(url=args.url, case_id=args.case, timeout=args.timeout,
                           capture_pcap=args.pcap, headless=args.headless, observe_only=args.observe)

        elif args.cmd == "canary":
            from .canary.server import run_canary
            run_canary(case_id=args.case, port=args.port)

        elif args.cmd == "deobfuscate":
            from .deobfuscate.core import DeobfuscationEngine
            engine = DeobfuscationEngine()
            
            content = ""
            if args.text:
                content = args.text
            elif args.file:
                if not os.path.exists(args.file):
                    handle_error("file_not_found", args.file)
                with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            elif args.url:
                content = args.url
            else:
                print("Error: Must provide --text, --file, or --url")
                sys.exit(1)
            
            artifacts = {
                "text": content,
                "urls": [content] if args.url else [],
                "html": "",
                "javascript": "",
                "attachments": []
            }
            results = engine.analyze_artifacts(artifacts)
            
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                print(f"Deobfuscation Results:")
                print(f"Assessment: {results['assessment_status']}")
                print(f"Text observations: {results['coverage']['text']['status']}")
                print(f"Text risk detection: {results['coverage']['text']['risk_detection']}")
                if results['suspicion_score'] is not None:
                    print(f"Transformation heuristic ({results['score_scope']}, uncalibrated): {results['suspicion_score']:.3f}")
                    print(f"Nontext transformation complexity: {results['complexity_rating']}")
                    print(f"Nontext techniques detected: {len(results['techniques_detected'])}")
                else:
                    print("Suspicion assessment: not_evaluated; text observations are descriptive only")
                print(results['limitation'])
                deobfuscated = results.get('deobfuscated_artifacts', {})
                if deobfuscated.get('urls'):
                    urls = deobfuscated['urls']
                    print(f"Deobfuscated URLs: {len(urls)}")
                    for url in urls[:5]:  # Show first 5
                        print(f"  {url}")
                if results.get('transformations'):
                    print(f"Transformations: {len(results['transformations'])}")
                    for trans in results['transformations'][:3]:  # Show first 3
                        print(f"  {trans.get('technique', 'unknown')}: {trans.get('description', '')}")
        elif args.cmd == "update":
            from .core.trace import update_report
            update_report(args.case)
        elif args.cmd == "monitor":
            from .sentinel import SentinelMonitor
            monitor = SentinelMonitor()

            if args.action == "start":
                monitor.start()
                print("✅ Sentinel monitoring started")
            elif args.action == "stop":
                monitor.stop()
                print("🛑 Sentinel monitoring stopped")
            elif args.action == "status":
                stats = monitor.get_stats()
                print("📊 Sentinel Status:")
                print(f"  Running: {stats['is_running']}")
                print(f"  Active campaigns: {stats['active_campaigns']}")
                print(f"  Unacknowledged alerts: {stats['unacknowledged_alerts']}")
            elif args.action == "add":
                if not args.case or not args.url:
                    print("❌ Error: --case and --url required for add action")
                    sys.exit(1)
                campaign_id = monitor.add_campaign(args.case, args.url)
                print(f"✅ Campaign added: {campaign_id}")
            elif args.action == "remove":
                if not args.case:
                    print("❌ Error: --case required for remove action")
                    sys.exit(1)
                # Find campaign by case_id
                campaigns = monitor.get_all_campaigns()
                campaign = next((c for c in campaigns if c['case_id'] == args.case), None)
                if campaign:
                    monitor.remove_campaign(campaign['id'])
                    print(f"✅ Campaign removed: {campaign['id']}")
                else:
                    print(f"❌ Campaign not found for case: {args.case}")
            elif args.action == "list":
                campaigns = monitor.get_all_campaigns()
                if campaigns:
                    print("📋 Active Campaigns:")
                    for campaign in campaigns:
                        print(f"  {campaign['id']}: {campaign['url']} ({campaign['status']})")
                else:
                    print("📋 No active campaigns")
            elif args.action == "check":
                results = monitor.check_now(args.campaign if hasattr(args, 'campaign') and args.campaign else None)
                if results:
                    print("🔍 Check Results:")
                    for result in results:
                        status_emoji = "✅" if result['status'] == 'up' else "❌" if result['status'] == 'down' else "⚠️"
                        print(f"  {status_emoji} {result['campaign_id']}: {result['status']} ({result.get('http_status', 'N/A')})")
                        if result.get('content_changed'):
                            print("    📝 Content changed!")
                        if result.get('error_message'):
                            print(f"    ❌ Error: {result['error_message']}")
                else:
                    print("📋 No campaigns to check")
            elif args.action == "files":
                from .sentinel import FileMonitor
                file_monitor = FileMonitor()
                changes = file_monitor.monitor_all_cases()
                if changes:
                    print("🔍 File Changes Detected:")
                    for change in changes:
                        print(f"\n📁 Case: {change['case_id']}")
                        print(f"   Integrity: {change['integrity_status']}")
                        if change['integrity_message']:
                            print(f"   Message: {change['integrity_message']}")
                        if change['new_files']:
                            print(f"   🆕 New files: {len(change['new_files'])}")
                        if change['modified_files']:
                            print(f"   ✏️  Modified files: {len(change['modified_files'])}")
                        if change['deleted_files']:
                            print(f"   🗑️  Deleted files: {len(change['deleted_files'])}")
                else:
                    print("✅ No file changes detected in any case")
            elif args.action == "integrity":
                from .sentinel import FileMonitor
                file_monitor = FileMonitor()
                report = file_monitor.generate_integrity_report()
                print("🔐 File Integrity Report:")
                print(f"   Total cases: {report['total_cases']}")
                print(f"   ✅ Integrity OK: {report['integrity_summary']['ok']}")
                print(f"   ❌ Compromised: {report['integrity_summary']['compromised']}")
                print(f"   ❓ Unknown: {report['integrity_summary']['unknown']}")
                print("\n📋 Case Details:")
                for case in report['cases']:
                    status_emoji = {'ok':'✅', 'unknown':'❓', 'compromised':'❌'}[case['integrity_status']]
                    print(f"   {status_emoji} {case['case_id']}: {case['file_count']} files - {case['integrity_message']}")

        elif args.cmd in ["geographic", "geo"]:
            from .sentinel.intelligence_analyzer import IntelligenceAnalyzer

            analyzer = IntelligenceAnalyzer(use_proxy=True)

            if args.action == "report":
                print(f"🗺️  Generando report geografico per case: {args.case or 'TUTTI'}")
                print(f"📊 Confidenza minima: {args.min_confidence}")

                report = analyzer.generate_geographic_report(args.case, args.min_confidence)

                if report['status'] == 'success':
                    print("✅ Report generato con successo!")
                    print(f"📊 Vittime analizzate: {report['total_victims']}")
                    print(f"🌍 Paesi coinvolti: {report['summary']['total_countries']}")
                    print(f"🚨 Livello rischio: {report['summary']['risk_assessment']['level']}")

                    if report['summary']['attacker_countries']:
                        print(f"🎯 Attaccanti da: {', '.join(report['summary']['attacker_countries'][:3])}")

                    print(f"\n📁 File generati nella directory reports/geographic/")

                else:
                    print(f"❌ Errore generazione report: {report.get('message', 'Errore sconosciuto')}")

            elif args.action == "stats":
                print(f"📊 Statistiche geografiche per case: {args.case or 'TUTTI'}")

                stats = analyzer.get_geographic_statistics(args.case, args.min_confidence)

                if 'error' not in stats:
                    print(f"📊 Vittime totali: {stats['total_victims']}")
                    print(f"🚨 Attaccanti identificati: {stats['attackers']} ({stats['attacker_percentage']:.1f}%)")

                    if stats['countries']:
                        print("🌍 Distribuzione per paese:")
                        for country, count in sorted(stats['countries'].items(), key=lambda x: x[1], reverse=True)[:5]:
                            print(f"  • {country}: {count}")
                else:
                    print(f"❌ Errore: {stats['error']}")

            elif args.action == "map":
                print("🗺️  Funzione mappa non ancora implementata")
                print("💡 Usa 'paw geographic report' per generare mappe interattive")

        else:
            parser.print_help()

    except FileNotFoundError as e:
        handle_error("file_not_found", str(e))
    except PermissionError as e:
        handle_error("permission_error", str(e))
    except Exception as e:
        # Check for specific error types
        error_str = str(e).lower()
        if "parse" in error_str or "header" in error_str:
            handle_error("parse_error", str(e))
        elif "network" in error_str or "connection" in error_str or "timeout" in error_str:
            handle_error("network_error", str(e))
        else:
            handle_error("generic", f"An unexpected error occurred: {str(e)}", 
                        details=f"Command: {args.cmd}\nFull traceback: {type(e).__name__}")
def show_main_help():
    """Show main help with examples."""
    help_text = """
🐾 PAW - Phishing Attribution Workbench

Commands:
  analyze     Analyze email(s) and generate attribution report
  quick       Fast analysis, no egress
  full        Complete analysis with detonation
  forensic    Strict profile + exports + optional anchoring
  detonate    Safely detonate URLs from analyzed case
  canary      Start passive tracking server
  geographic  Generate geographic intelligence reports
  query       Search case database
  export      Export case in various formats
  verify      Verify evidence integrity
  help        Show help for commands

Examples:
  paw analyze email.eml                    # Quick analysis
  paw analyze email.eml --forensic         # Request optional anchoring
  paw analyze email.eml --stix --abuse     # With exports
  paw quick email.eml                      # Fast preset
  paw full email.eml                       # Complete analysis
  paw forensic email.eml                   # Strict profile, exports, optional anchoring

For detailed help: paw help <command>
"""
    print(help_text)


def show_command_help(topic):
    """Show detailed help for a specific command."""
    help_topics = {
        "analyze": """
🐾 PAW ANALYZE - Email Analysis

Analyze phishing emails and generate comprehensive attribution reports.

USAGE:
  paw analyze <email> [options]

OPTIONS:
  --profile PROFILE    Scoring profile (default, strict, conservative)
  --stix               Request STIX; conformance currently unavailable
  --abuse              Generate abuse package
  --forensic           Request optional anchoring; profile/exports unchanged
  --no-egress          Do not contact suspicious infrastructure
  --lang LANG          Abuse-package language (it or en fallback); main reports English

EXAMPLES:
  paw analyze suspicious.eml
  paw analyze inbox/ --profile strict
  paw analyze email.eml --stix --abuse --forensic
""",
        "quick": """
🐾 PAW QUICK - Fast Analysis

Perform rapid phishing analysis without external network contact.

USAGE:
  paw quick <email>

This is equivalent to:
  paw analyze <email> --no-egress --profile default

Perfect for initial triage when you want results quickly.
""",
        "full": """
🐾 PAW FULL - Complete Analysis

Perform comprehensive analysis including detonation and exports.

USAGE:
  paw full <email>

This is equivalent to:
  paw analyze <email> --stix --abuse --profile strict

Uses the common pipeline with strict scoring and both export packages.
With --no-egress, detonation and network enrichment are skipped.
Unavailable checks remain explicit; this preset does not guarantee full coverage.
""",
        "forensic": """
🐾 PAW FORENSIC - Strict Profile and Optional Anchoring

Use strict scoring and both exports, with optional anchoring if keys and network
are available. --no-egress excludes anchoring and other external stages.

USAGE:
  paw forensic <email>

This is equivalent to:
  paw analyze <email> --stix --abuse --forensic --profile strict

This preset shares the common analysis pipeline. Rekor inclusion verification
is not implemented; anchoring does not establish actor identity.
""",
        "detonate": """
🐾 PAW DETONATE - URL Detonation

Safely detonate URLs found in analyzed emails.

USAGE:
  paw detonate --case <case_id> [options]
  paw detonate --url <url> [options]

OPTIONS:
  --timeout SEC        Timeout in seconds (default: 35)
  --pcap               Capture network traffic
  --headless           Run in headless mode (default)
  --observe            Block dangerous HTTP methods

EXAMPLES:
  paw detonate --case case-20251029-abc123
  paw detonate --url https://suspicious-site.com --pcap
""",
        "canary": """
🐾 PAW CANARY - Passive Tracking

Deploy passive tracking server to monitor attacker interactions.

USAGE:
  paw canary --case <case_id> [options]

OPTIONS:
  --port PORT          Server port (default: 8787)

The canary server captures IP addresses and metadata from attackers
who interact with the phishing infrastructure.
""",
        "export": """
🐾 PAW EXPORT - Export Cases

Export analyzed cases in various formats.

USAGE:
  paw export --case <case_id> --format <format>

FORMATS:
  zip                 Standard ZIP archive

EXAMPLES:
  paw export --case case-20251029-abc123 --format zip
""",
        "query": """
🐾 PAW QUERY - Search Cases

Search historical cases by indicators.

USAGE:
  paw query --by <type> --value <value> [options]

TYPES:
  ip                  Search by IP address
  domain              Search by domain name
  asn                 Search by ASN
  org                 Search by organization

OPTIONS:
  --days DAYS         Look back days (default: 30)

EXAMPLES:
  paw query --by ip --value 192.168.1.1
  paw query --by domain --value evil.com --days 90
""",
        "geographic": """
🐾 PAW GEOGRAPHIC - Intelligence Geographic Reports

Generate geographic intelligence reports showing attacker locations and victim distributions.

USAGE:
  paw geographic <action> [options]

ACTIONS:
  report              Generate full geographic report with maps and statistics
  stats               Show geographic statistics summary
  map                 Generate interactive map (future feature)

OPTIONS:
  --case CASE         Case ID to analyze (optional, analyzes all if not specified)
  --min-confidence F  Minimum confidence threshold (0.0-1.0, default: 0.0)
  --output FORMAT     Output format: html, json, both (default: both)

EXAMPLES:
  paw geographic report                              # Full report for all cases
  paw geographic report --case PHISHING_001         # Report for specific case
  paw geographic stats --min-confidence 0.5         # Stats with confidence filter
  paw geographic report --output html               # HTML report only
"""
    }

    if topic in help_topics:
        print(help_topics[topic])
    else:
        print(f"❌ Unknown help topic: {topic}")
        print("Available topics: analyze, quick, full, forensic, detonate, canary, geographic, export, query")


if __name__ == "__main__":
    main()
