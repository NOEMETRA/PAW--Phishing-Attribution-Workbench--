"""Publish a private root tree for reading, without transferring ownership.

Only a fresh root0700 directory under protected root ancestors is accepted.
Descriptors pin every changed inode, symlinks/hardlinks/special files refuse,
and the top directory stays private until the last permission operation.
"""
import os
from pathlib import Path
import stat

ROOT_UID = 0
MAX_ENTRIES = 8192


def require(value, reason):
    if not value: raise ValueError(reason)


def publish_reader_tree(path, reader_gid=1000):
    require(os.geteuid() == ROOT_UID and isinstance(path, Path) and path.is_absolute() and
            '..' not in path.parts and type(reader_gid) is int and reader_gid >= 0, 'export_root_fixed_tree')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:-1]:
            value = os.fstat(parent)
            require(value.st_uid == ROOT_UID and value.st_mode & 0o022 == 0, 'export_protected_ancestor')
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent); parent = child
        value = os.fstat(parent)
        require(value.st_uid == ROOT_UID and value.st_mode & 0o022 == 0, 'export_protected_parent')
        root = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    finally: os.close(parent)
    try:
        value = os.fstat(root)
        require(value.st_uid == ROOT_UID and stat.S_IMODE(value.st_mode) == 0o700, 'export_private_root_required')
        count = 0
        def visit(fd, depth):
            nonlocal count
            require(depth <= 16, 'export_depth_budget')
            names = os.listdir(fd); count += len(names)
            require(count <= MAX_ENTRIES, 'export_entry_budget')
            for name in names:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                require(info.st_uid == ROOT_UID and info.st_mode & 0o022 == 0 and
                        (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)), 'export_private_inode_required')
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                directory = stat.S_ISDIR(info.st_mode)
                child = os.open(name, flags | (os.O_DIRECTORY if directory else 0), dir_fd=fd)
                try:
                    pinned = os.fstat(child)
                    require((pinned.st_dev, pinned.st_ino) == (info.st_dev, info.st_ino) and
                            (directory or pinned.st_nlink == 1), 'export_inode_changed_or_linked')
                    if directory: visit(child, depth+1)
                    os.fchown(child, ROOT_UID, reader_gid)
                    os.fchmod(child, 0o750 if directory else 0o440)
                finally: os.close(child)
        visit(root, 0)
        os.fchown(root, ROOT_UID, reader_gid)
        # No privileged path operations take place after publishing traversal.
        os.fchmod(root, 0o750)
    finally: os.close(root)
