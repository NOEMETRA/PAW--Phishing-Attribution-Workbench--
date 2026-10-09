"""Explicit input selection and per-email failures for directory analyses."""
from pathlib import Path


class BatchAnalysisError(RuntimeError):
    def __init__(self, paths, failures, inputs):
        self.case_paths = paths
        self.failures = failures
        self.inputs = inputs
        super().__init__(f'Batch incomplete: {len(paths)} completed, {len(failures)} failed; see worker result for individual inputs')


def select_inputs(source):
    source = Path(source)
    if source.is_file():
        if source.suffix.lower() not in {'.eml', '.msg'}:
            raise ValueError('Unsupported input extension; provide original EML')
        return [source]
    if not source.is_dir():
        raise FileNotFoundError(str(source))
    paths = sorted((path for path in source.iterdir()
                    if path.is_file() and path.suffix.lower() in {'.eml', '.msg'}),
                   key=lambda path: (path.name.casefold(), path.name))
    if not paths:
        raise ValueError('No EML/MSG inputs found in directory')
    return paths
