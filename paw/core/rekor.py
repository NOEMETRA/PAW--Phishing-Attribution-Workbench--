
import os, json, requests, base64, hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.backends import default_backend

def _load_private_key(pem_path: str):
    with open(pem_path, "rb") as f:
        data = f.read()
    try:
        return serialization.load_pem_private_key(data, password=None, backend=default_backend())
    except Exception as e:
        raise RuntimeError(f"Failed to load private key: {e}")

def _load_public_key_pem(pub_path: str):
    with open(pub_path, "rb") as f:
        return f.read()

def _sign(statement_bytes: bytes, key):
    if isinstance(key, rsa.RSAPrivateKey):
        sig = key.sign(
            statement_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return sig, "rsa"
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        sig = key.sign(statement_bytes, ec.ECDSA(hashes.SHA256()))
        return sig, "ecdsa"
    else:
        raise RuntimeError("Unsupported key type for signing. Use RSA or EC private key.")

def anchor_case(case_dir: str, rekor_url: str, privkey_path: str, pubkey_path: str):
    """Creates a deterministic statement from case evidence and anchors to Rekor as hashedrekord."""
    # Build statement from evidence index + root
    idx_path = os.path.join(case_dir, "evidence", "merkle_index.json")
    root_path = os.path.join(case_dir, "evidence", "merkle_root.bin")
    if not (os.path.exists(idx_path) and os.path.exists(root_path)):
        raise RuntimeError("Evidence index or root missing; run trace first.")
    with open(idx_path, "r", encoding="utf-8") as f: idx = json.load(f)
    with open(root_path, "r", encoding="utf-8") as f: root = f.read().strip()
    manifest_path = os.path.join(case_dir, "manifest.json")
    with open(manifest_path, "r", encoding="utf-8") as f: manifest = json.load(f)

    statement = {
        "type": "paw.evidence.v1",
        "case_id": manifest.get("case_id"),
        "created_utc": manifest.get("created_utc"),
        "merkle_root_blake3": root,
        "files": [{"path": k, "blake3": v} for k,v in sorted(idx.items())],
    }
    stmt_bytes = json.dumps(statement, separators=(",",":"), sort_keys=True).encode("utf-8")
    # Save statement for audit
    stmt_path = os.path.join(case_dir, "evidence", "rekor_statement.json")
    with open(stmt_path, "w", encoding="utf-8") as f: json.dump(statement, f, indent=2)

    # Sign statement
    key = _load_private_key(privkey_path)
    signature, keytype = _sign(stmt_bytes, key)
    pub_pem = _load_public_key_pem(pubkey_path)

    # Hash of statement (sha256 for Rekor 'hashedrekord')
    sha256_hex = hashlib.sha256(stmt_bytes).hexdigest()

    # Build proposedEntry for hashedrekord
    proposed = {
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {
                "hash": {"algorithm": "sha256", "value": sha256_hex}
            },
            "signature": {
                "content": base64.b64encode(signature).decode("ascii"),
                "publicKey": {"content": base64.b64encode(pub_pem).decode("ascii")}
            }
        }
    }

    # Submit to Rekor
    url = rekor_url.rstrip("/") + "/api/v1/log/entries"
    r = requests.post(url, json=proposed, timeout=20)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Rekor returned {r.status_code}: {r.text}")
    resp = r.json()
    # Response is a dict keyed by UUID (entry UUID)
    entry = next(iter(resp.values()))
    out = {
        "rekor_url": rekor_url,
        "entry_uuid": entry.get("uuid") or entry.get("logID"),
        "integratedTime": entry.get("integratedTime"),
        "logIndex": entry.get("logIndex"),
        "body": entry.get("body"),
        "statement_sha256": sha256_hex
    }
    out_path = os.path.join(case_dir, "evidence", "rekor_anchor.json")
    with open(out_path, "w", encoding="utf-8") as f: json.dump(out, f, indent=2)
    return out_path

def fetch_inclusion_proof(rekor_url: str, entry_uuid: str) -> dict:
    """Fetch inclusion proof for a Rekor entry."""
    url = f"{rekor_url.rstrip('/')}/api/v1/log/entries/{entry_uuid}"
    r = requests.get(url, timeout=20)
    if r.status_code != 200:
        raise RuntimeError(f"Failed to fetch inclusion proof: {r.status_code}: {r.text}")
    
    entry = r.json()
    # Extract inclusion proof data
    proof = {
        "entry_uuid": entry_uuid,
        "logIndex": entry.get("logIndex"),
        "integratedTime": entry.get("integratedTime"),
        "treeSize": entry.get("verification", {}).get("inclusionProof", {}).get("treeSize"),
        "rootHash": entry.get("verification", {}).get("inclusionProof", {}).get("rootHash"),
        "hashes": entry.get("verification", {}).get("inclusionProof", {}).get("hashes", [])
    }
    return proof

def verify_inclusion_proof(proof: dict, statement_sha256: str) -> bool:
    """No validated Rekor verifier is implemented; field presence is not a proof."""
    return False
