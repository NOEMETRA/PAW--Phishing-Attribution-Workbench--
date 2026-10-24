"""Explicit root capture of post-maintenance facts and signed guest inventory."""
import os
from pathlib import Path
import subprocess

import hash_authorization as auth
from offline_candidate import canonical,require
from benign_guest_validation import BASE,digest
from verify_granted_offline import regular

SIGNER='D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81'
MANIFEST_SHA='6cd96c00a9a7f3b77233af758968d94e83f9cec396a1b5035ccd8688a26aa804'


def install(vendor_manifest,notes):
    require(os.geteuid()==0,'root_operator_required')
    # Trust the root-owned signed image preparation and installed vendor keyring.
    for path in [BASE,BASE.parent/'SHA256SUMS',BASE.parent/'SHA256SUMS.gpg',Path('/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg')]:
        auth.fs.trusted(path.lstat())
    verified=subprocess.run(['/usr/bin/gpgv','--status-fd=1','--keyring','/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg',
              str(BASE.parent/'SHA256SUMS.gpg'),str(BASE.parent/'SHA256SUMS')],capture_output=True,text=True,timeout=15)
    require(verified.returncode==0 and '[GNUPG:] VALIDSIG '+SIGNER+' ' in verified.stdout,'guest_vendor_signature')
    sums={p[1].lstrip('*'):p[0] for line in (BASE.parent/'SHA256SUMS').read_text().splitlines() if len(p:=line.split())==2}
    raw=regular(vendor_manifest,65536)
    require(auth.digest(raw)==MANIFEST_SHA==sums.get('ubuntu-24.04-minimal-cloudimg-amd64.manifest') and
            digest(BASE)==sums.get(BASE.name)==auth.fs.IMAGE_SHA256,'guest_signed_bytes')
    packages=dict(line.split(None,1) for line in raw.decode().splitlines() if len(line.split(None,1))==2)
    require(packages.get('linux-image-6.8.0-147-generic')=='6.8.0-147.147','guest_kernel_inventory')
    context=auth.capture();auth.validate_context(context)
    record={'schema':'paw-s14-maintenance-v2','packages':context['host']['packages'],'kernel':context['host']['kernel'],
       'image_sha256':context['host']['image_sha256'],'qemu_binary_sha256':context['qemu_binary_sha256'],
       'qemu_components':context['qemu_components'],'dpkg_inventory_sha256':context['dpkg_inventory_sha256'],
       'host_identity_sha256':context['host_identity_sha256'],'cpu_signature':context['cpu_signature'],
       'vendor_manifest_sha256':MANIFEST_SHA,'vendor_signer':SIGNER,'guest_kernel_release':'6.8.0-147-generic',
       'reboot_required':Path('/var/run/reboot-required').exists(),'review_notes':notes}
    data=canonical(record);auth.validate_maintenance(data,context)
    try:auth.ROOT.mkdir(mode=0o700)
    except FileExistsError:pass
    with auth.store() as fd:
        name='maintenance-'+auth.digest(data)+'.json'
        try:auth.fs.exclusive(fd,name,data)
        except FileExistsError:require(auth.fs.read(fd,name)==data,'existing_maintenance_changed')
    return data,verified.stdout
