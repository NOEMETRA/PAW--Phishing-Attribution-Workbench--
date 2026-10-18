# Legacy standalone IP-analysis launcher

`python run_analyzer.py` explicitly reports unavailability and exits 1 before
importing Sentinel or accessing saved sources. Help exits 0, unsupported arguments
exit 2 and import is inert. Direct invocation requires only the standard library.
No replacement collection command, case selector or worker option is added.

The former launcher ignored arguments, selected a hardcoded historical case and
constructed a writable `IntelligenceAnalyzer("sentinel.db", use_proxy=False)`.
An actual guarded `--help` invocation in an empty directory created a database
and returned a zero-analysis success message. On actual saved SQLite with a
deliberately invalid IP, `--help` changed a `captured` row to `analyzed`, changed
its score/interaction fields and returned one analysis with zero errors. The
existing requests capability-probe import preceded the guard in this baseline
probe; the invalid-IP fixture required no target lookup or request. This is not
evidence of live collection, cold-bootstrap containment or classifier accuracy.

This disposition removes only that unsafe standalone entry path. Original
SQLite records, configuration and stored JSON evidence remain intact. Existing
passive inspection through `check_victims.py` and
`IntelligenceAnalyzer(db_path, read_only=True).generate_intelligence_report(...)`
remains available, retaining unverified source records rather than performing
IP analysis. Passive reporting is not an active-analysis substitute.

The package's writable constructor and IP-analysis/update methods are unchanged
and remain unvalidated S14 work. Fixing argument handling alone would still
expose unsupervised collection and successful updates after failed observations.
Any future active launcher requires verified isolation/egress, source selection,
supervision, bounded execution, observation/error accounting and honest update
semantics. Do not infer that these issues are fixed inside the package.

`integration_legacy_analyzer_real.py` checks 25 fresh guarded legacy paths,
including nine actual missing/saved/configured/corrupt/incomplete/journal/WAL/
configuration-error source trees, help/import/arguments and explicit `main`
calls. Two direct standard-library invocations run outside the checkout without
`PYTHONPATH`. File/SQLite audit hooks reject observed access; source snapshots,
no blocked network attempts, no Sentinel/requests imports and unchanged threads
and process arguments are checked. The hooks do not cover every metadata syscall
and are not OS isolation. Two actual cold passive reports retain both pending
fixture rows, original invalid-UTF8/duplicate JSON evidence, unverified scope
and unavailable risk/identity conclusions without changing saved storage. These
are constructed storage regressions, not captures or real-world accuracy tests.
