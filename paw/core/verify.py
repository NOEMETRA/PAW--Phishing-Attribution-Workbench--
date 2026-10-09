
import os, json
import blake3

def verify_case(case_dir):
    idx_path = os.path.join(case_dir, "evidence", "merkle_index.json")
    root_path = os.path.join(case_dir, "evidence", "merkle_root.bin")
    if not (os.path.exists(idx_path) and os.path.exists(root_path)):
        print("[verify] evidence index or root missing")
        return False
    with open(idx_path,"r",encoding="utf-8") as f: idx = json.load(f)
    # Modern cases enumerate all files. Added/unindexed artifacts must fail verification.
    scope_path = os.path.join(case_dir, 'evidence', 'inventory_scope.json')
    if os.path.exists(scope_path):
        from .evidence import file_inventory
        try:
            actual = file_inventory(case_dir)
            if set(actual) != set(idx):
                print('[verify] unindexed or missing case files')
                return False
        except ValueError as exc:
            print(f'[verify] invalid inventory: {exc}')
            return False
    # recompute file hashes
    recomputed = {}
    for rel, h in idx.items():
        from pathlib import Path
        root = Path(case_dir).resolve()
        full = (root / rel).resolve()
        if not full.is_relative_to(root):
            print('[verify] indexed path outside case')
            return False
        if not os.path.exists(full):
            print(f"[verify] missing file in case: {rel}")
            return False
        with open(full, "rb") as fh:
            digest = blake3.blake3()
            while chunk := fh.read(1024*1024): digest.update(chunk)
            recomputed[rel] = digest.hexdigest()
    if recomputed != idx:
        print("[verify] mismatch in evidence index")
        return False
    # recompute root: blake3 of concatenated hashes sorted by path
    concat = "".join(v for k,v in sorted(recomputed.items()))
    root2 = blake3.blake3(concat.encode()).hexdigest()
    with open(root_path,"r",encoding="utf-8") as f: root = f.read().strip()
    ok = (root == root2)
    print("[verify] Merkle root: OK" if ok else "[verify] Merkle root: BAD")
    
    # Check Rekor inclusion proof if available
    proof_path = os.path.join(case_dir, "evidence", "rekor_proof.json")
    anchor_path = os.path.join(case_dir, "evidence", "rekor_anchor.json")
    if os.path.exists(proof_path) and os.path.exists(anchor_path):
        try:
            from .rekor import verify_inclusion_proof
            with open(proof_path, "r", encoding="utf-8") as f:
                proof = json.load(f)
            with open(anchor_path, "r", encoding="utf-8") as f:
                anchor = json.load(f)
            statement_sha256 = anchor.get("statement_sha256")
            proof_ok = verify_inclusion_proof(proof, statement_sha256)
            print("[verify] Rekor inclusion: OK" if proof_ok else "[verify] Rekor inclusion: BAD")
            ok = ok and proof_ok
        except Exception as e:
            print(f"[verify] Rekor inclusion check failed: {e}")
            ok = False
    elif os.path.exists(anchor_path):
        print("[verify] Rekor anchored but no inclusion proof available")
        ok = False
    
    return ok
