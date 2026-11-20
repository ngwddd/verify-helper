"""Create private verification evidence on POSIX and Windows."""
from __future__ import annotations

import os
import stat
import uuid
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def _windows_identity():
    import win32api
    import win32con
    import win32security

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        return win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    finally:
        token.Close()


def _windows_attributes(*, directory):
    import pywintypes
    import win32security

    sid = win32security.ConvertSidToStringSid(_windows_identity())
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    flags = "OICI" if directory else ""
    attributes.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        f"D:P(A;{flags};FA;;;{sid})", win32security.SDDL_REVISION_1)
    return attributes


def require_private(path: Path, *, directory: bool = False) -> None:
    entry = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(entry.st_mode) or getattr(entry, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise ValueError("Evidence path is not a regular private object")
    if not directory and entry.st_nlink != 1:
        raise ValueError("Evidence file cannot have multiple links")
    if os.name != "nt":
        if entry.st_uid != os.geteuid() or entry.st_mode & 0o077:
            raise ValueError("Evidence path is accessible to another system account")
        return
    import win32security

    acl = win32security.GetNamedSecurityInfo(
        str(path), win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION,
    ).GetSecurityDescriptorDacl()
    if acl is None or acl.GetAceCount() != 1:
        raise ValueError("Evidence path must have a private access list")
    (ace_type, _), _, sid = acl.GetAce(0)
    if ace_type != 0 or sid != _windows_identity():
        raise ValueError("Evidence access list grants access to another identity")


def _require_safe_parents(path: Path) -> None:
    for ancestor in reversed(path.absolute().parent.parents):
        _check_parent(ancestor)
    _check_parent(path.absolute().parent)


def _create_evidence_parents(path: Path) -> None:
    missing = []
    for ancestor in (path, *path.parents):
        try:
            _check_parent(ancestor)
            break
        except FileNotFoundError:
            missing.append(ancestor)
    for ancestor in reversed(missing):
        ancestor.mkdir(mode=0o700, exist_ok=True)
        _check_parent(ancestor)


def _check_parent(path: Path) -> None:
    entry = path.lstat()
    if not stat.S_ISDIR(entry.st_mode) or getattr(entry, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise ValueError("Evidence cannot traverse a link or junction")
    if os.name != "nt" and (entry.st_uid not in (0, os.geteuid())
                            or entry.st_mode & 0o022 and not entry.st_mode & stat.S_ISVTX):
        raise ValueError("Evidence parent can be replaced by another user")


def private_directory(path: Path, *, exist_ok: bool = False) -> None:
    _create_evidence_parents(path.absolute().parent)
    _require_safe_parents(path)
    if os.name == "nt":
        import pywintypes
        import win32file

        try:
            win32file.CreateDirectory(str(path), _windows_attributes(directory=True))
        except pywintypes.error as error:
            if not exist_ok or error.winerror != 183:
                raise OSError("Cannot create private evidence directory") from error
    else:
        path.mkdir(mode=0o700, exist_ok=exist_ok)
    require_private(path, directory=True)


def private_write(path: Path, data: bytes) -> None:
    """Publish bytes atomically from a file that starts with private permissions."""
    _require_safe_parents(path)
    temporary = path.with_name(f".vh-write-{uuid.uuid4().hex}")
    if os.name == "nt":
        import msvcrt
        import win32con
        import win32file

        handle = win32file.CreateFile(str(temporary), win32con.GENERIC_WRITE, 0,
                                      _windows_attributes(directory=False), win32con.CREATE_NEW,
                                      win32con.FILE_ATTRIBUTE_NORMAL, None)
        fd = msvcrt.open_osfhandle(handle.Detach(), os.O_WRONLY | os.O_BINARY)
    else:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        require_private(temporary)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
