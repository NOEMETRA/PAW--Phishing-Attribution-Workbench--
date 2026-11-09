"""Fixed private fixture readiness, with stopped-role errors; no VM or URLs."""
import hashlib
import os
from pathlib import Path
import time
import uuid

from . import mail_browser_public as public


def require_snapshot(release):
    public.need(os.geteuid() == 0 and Path(__file__).resolve() ==
                Path('/opt/paw-vm/releases') / release / 'paw/core' / Path(__file__).name,
                'mail_fixture_diagnostic_snapshot')


def run(job, release, *, plain_http=False):
    """Called inside the fixed owned preparation's lock and coordinator budget."""
    require_snapshot(release)
    public.need(type(plain_http) is bool, 'mail_fixture_diagnostic_selection')
    epoch = uuid.uuid4().hex
    public.identity(job, epoch, release)
    parent = public.kernel.unit_properties('paw-vm-owned-' + job + '.service')
    expected = {'ActiveState': 'active', 'MainPID': str(os.getpid()),
                'MemoryMax': str(192 * 1024**2), 'MemorySwapMax': '0',
                'TasksMax': '24', 'CPUQuotaPerSecUSec': '350ms'}
    public.need(all(parent.get(k) == v for k, v in expected.items()),
                'mail_fixture_diagnostic_parent_budget')
    from vm_runtime_revalidation import snapshot, network_state
    public.require_idle()
    before, network = snapshot(), network_state()
    actors, prep = [], None
    record = {'schema': 'paw-mail-owned-tls-fixture-v1', 'result': 'FAIL',
              'job': job, 'epoch': epoch, 'release_sha': release,
              'vm_started': False, 'real_connections': 0, 'native_authority_created': False,
              'scope': 'Private owned fixture/transport readiness only; no TLS handshake, HTTP, VM or public readiness'}
    if plain_http:
        record.update(schema='paw-mail-owned-plain-http-v1', timing_ns={},
                      scope='Fixed private plain HTTP transport; no browser, TLS or public connection')
    mediation = None
    try:
        folder, _ = public.prepare_network(job, epoch, release, 'owned-browser', {})
        prep = public.NetworkPreparation(job, epoch, release, 'owned-browser', actors,
                                         protocol=True)
        deadline = time.monotonic() + 5
        while not prep.poll():
            public.need(time.monotonic() < deadline, 'mail_fixture_diagnostic_deadline')
            time.sleep(.02)
        public.need(all(actor.process.poll() is None for actor in actors),
                    'mail_fixture_diagnostic_unexpected_exit')
        if plain_http:
            from . import browser_owned_broker as broker
            began = time.monotonic_ns()
            record['timing_ns']['actors_ready'] = began
            mediation = broker.fixture_mediation(prep, epoch, began, None, mail_fixture=True)
            # Fixed probe only. Reuse the checked private roles with a fresh
            # ledger whose first and only admitted URL is the owned HTTP seed.
            mediation.ledger = public.mediator.BrowserRequestLedger(broker.PLAIN_HTTP_SEED, epoch, began)
            broker.probe_plain_http(mediation, epoch, record)
            broker.stop_network_roles(mediation, actors, folder, epoch, prep.inode, record)
        record['result'] = 'PASS'
    except Exception as error:
        record['error'] = type(error).__name__ + ':' + str(error)[:512]
    finally:
        # No role error can be published until all writers/readers have stopped.
        public.kernel.cleanup_actors(actors)
        public.kernel.vacant_ids()
        public.need(snapshot() == before and network_state() == network,
                    'mail_fixture_diagnostic_restore')
        record.update(writers_stopped=True, host_restored=True)
        if mediation is not None:
            record['observations'] = mediation.observations
        record['preparation'] = {} if prep is None else {
            name: getattr(prep, name) for name in
            ['fixture_configured', 'server_live', 'worker_live', 'ready']}
        public.need(len(actors) <= 3, 'mail_fixture_diagnostic_role_budget')
        record['roles'] = []
        for actor in actors:
            raw = bytes(actor.errors)
            public.need(len(raw) <= 8192, 'mail_fixture_diagnostic_stderr_budget')
            record['roles'].append({'unit': actor.unit,
                'launcher_returncode': actor.process.poll(), 'stderr_bytes': len(raw),
                'stderr_sha256': hashlib.sha256(raw).hexdigest(),
                'stderr': raw[:4096].decode('utf-8', 'replace'),
                'stderr_truncated': len(raw) > 4096,
                'witness': getattr(actor, 'observation', None)})
    return record


def run_plain_http(job, release):
    """Run and publish the standalone fixed probe before consuming a browser input."""
    require_snapshot(release)
    public.identity(job, '0' * 32, release)
    import one_use_authorization as fs
    from reader_export import publish_reader_tree

    with fs.execution_lock():
        with public._owned_preparation_budget(job):
            proof = run(job, release, plain_http=True)
        raw = public.canonical(proof)
        public.need(len(raw) <= 32768, 'mail_fixture_plain_http_diagnostic_budget')
        target = public.EXPORT_ROOT / ('owned-plain-http-' + job)
        with fs.root_directory(target.parent):
            target.mkdir(mode=0o700)
        with fs.root_directory(target) as fd:
            fs.exclusive(fd, 'attestation.json', raw)
        publish_reader_tree(target)
    return proof
