"""Gated, offline worker for standalone deobfuscation; never creates a case."""
import json
from pathlib import Path
import sys

from .core.runtime import wait_for_gate, mark_stage, atomic_json


def main():
    wait_for_gate()  # Containment precedes analysis imports and input access.
    from .core.network_policy import offline_policy
    with offline_policy(True):
        from .deobfuscate.input import analyze_input
        request = Path(sys.argv[1])
        options = json.loads(request.read_text(encoding='utf-8'))
        mark_stage('standalone_deobfuscation')
        try:
            result = analyze_input(**options)
        except (OSError, ValueError, TypeError) as exc:
            response = {'status':'input_error', 'error':str(exc)}
        else:
            response = {'status':'completed', 'result':result}
        atomic_json(request.parent/'result.json', response)


if __name__ == '__main__': main()
