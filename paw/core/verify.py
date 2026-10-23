
import os, json
import blake3

def verify_case(case_dir):
    """Return inventory/content integrity only; signatures/anchors are separate."""
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
    
    # Circular provider metadata is excluded by the existing inventory policy.
    # Its presence cannot turn an unavailable verifier into a pass or a failure
    # of the independently checked content inventory.
    proof_path = os.path.join(case_dir, "evidence", "rekor_proof.json")
    anchor_path = os.path.join(case_dir, "evidence", "rekor_anchor.json")
    if os.path.exists(proof_path) or os.path.exists(anchor_path):
        print('[verify] Rekor inclusion: NOT_EVALUATED; provider fields are unverified and excluded from the content inventory')
    
    return ok
