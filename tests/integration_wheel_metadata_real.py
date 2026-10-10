"""Build a real wheel and check its Python requirement, entry point and sources."""
import configparser
from email.parser import Parser
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import zipfile

REPO = Path(__file__).resolve().parents[1]


def main():
    project = tomllib.loads((REPO/'pyproject.toml').read_text(encoding='utf-8'))['project']
    with tempfile.TemporaryDirectory(prefix='paw-wheel-check-') as temporary:
        root = Path(temporary)
        source = root/'source'
        # Build outside the checkout. Include working-tree changes to tracked
        # sources so the same check can reproduce a failure before committing.
        files = subprocess.check_output(['git', '-C', str(REPO), 'ls-files', '-z'])
        for name in os.fsdecode(files).split('\0'):
            if not name:
                continue
            original = REPO/name
            if not original.is_file():
                continue
            target = source/name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(original.read_bytes())
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
        env.pop('PYTHONPATH', None)
        result = subprocess.run([sys.executable, '-X', 'utf8', '-m', 'pip', 'wheel',
            '--disable-pip-version-check', '--no-deps', '--wheel-dir', str(root/'wheel'),
            str(source)], cwd=root, env=env, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=180)
        assert result.returncode==0, result.stdout.decode('utf-8', errors='replace')
        wheel, = (root/'wheel').glob('paw-*.whl')
        with zipfile.ZipFile(wheel) as archive:
            metadata_path, = (name for name in archive.namelist() if name.endswith('.dist-info/METADATA'))
            metadata = Parser().parsestr(archive.read(metadata_path).decode('utf-8'))
            assert metadata['Requires-Python']==project['requires-python'], {
                'wheel':metadata['Requires-Python'], 'project':project['requires-python']}
            config = configparser.ConfigParser()
            config.read_string(archive.read(metadata_path.rsplit('/', 1)[0]+'/entry_points.txt').decode('utf-8'))
            assert dict(config['console_scripts'])==project['scripts']
            sources = list((source/'paw').rglob('*.py'))
            for path in sources:
                assert archive.read(path.relative_to(source).as_posix())==path.read_bytes(), path
        print(f'PASS: actual wheel Requires-Python={metadata["Requires-Python"]} matches pyproject; console scripts and {len(sources)} Python sources match. This build check does not install dependencies or prove analysis accuracy.')


if __name__=='__main__':
    main()
