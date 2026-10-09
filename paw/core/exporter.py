
import os, zipfile
from pathlib import Path
import uuid
from .evidence import file_inventory

def export_case(case_dir, fmt):
    if fmt != 'zip': raise ValueError('Only ZIP export is supported')
    root = Path(case_dir).resolve()
    if not root.is_dir(): raise FileNotFoundError(f'Case directory not found: {root}')
    file_inventory(root)  # Reject links and paths outside the case, including excluded files.
    files = sorted(path for path in root.rglob('*') if path.is_file())
    if not files: raise ValueError('Cannot export an empty case directory')
    base = str(root)
    case_id = os.path.basename(base)
    out = base + ".zip"
    temporary = root.with_name(root.name + '.' + uuid.uuid4().hex + '.zip.tmp')
    try:
        with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as z:
            z.comment = b'File archive; export alone does not establish case integrity or origin. Use paw verify.'
            for path in files:
                z.write(path, arcname=f'{case_id}/{path.relative_to(root).as_posix()}')
        temporary.replace(out)
    finally:
        temporary.unlink(missing_ok=True)
    
    # PGP sign the zip file if keys available
    if os.environ.get("PAW_PGP_PRIV"):
        try:
            from .signature import sign_file_pgp
            sig_path = out + ".asc"
            sign_file_pgp(out, os.environ["PAW_PGP_PRIV"], os.environ.get("PAW_PGP_PASS"), sig_path)
            print(f"[pgp] export signed: {sig_path}")
        except Exception as e:
            print(f"[pgp] signing failed: {e}")
    
    print(out)
    return out
