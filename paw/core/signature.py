"""PGP publication is unavailable pending independent signer/proof acceptance."""


def sign_file_pgp(path: str, pgp_priv_path: str, passphrase: str | None, out_sig: str) -> str:
    """Reject before inspecting paths/keys or publishing an unvalidated proof."""
    raise RuntimeError('PGP signing unavailable: signer/proof acceptance is not validated')
