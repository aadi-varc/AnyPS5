import hashlib
from pathlib import Path
import re
import zipfile

import import_audit


def library_platform(path, data, platform):
    if platform == "windows":
        if data[:2] != b"MZ":
            raise import_audit.AuditError(f"{path}: Windows libraries must be PE32+ x86-64 images")
        header = import_audit.unpack("<I", data, 0x3c, path, "PE header offset")[0]
        signature = import_audit.unpack("<I", data, header, path, "PE signature")[0]
        machine = import_audit.unpack("<H", data, header + 4, path, "PE machine")[0]
        magic = import_audit.unpack("<H", data, header + 24, path, "PE optional header magic")[0]
        if signature != 0x4550 or machine != 0x8664 or magic != 0x20b:
            raise import_audit.AuditError(f"{path}: Windows libraries must be PE32+ x86-64 images")
    else:
        if data[:4] != b"\x7fELF":
            raise import_audit.AuditError(f"{path}: Linux libraries must be little-endian ELF64 x86-64 images")
        header = import_audit.unpack("<16sHHIQQQIHHHHHH", data, 0, path, "ELF header")
        if header[0][4] != 2 or header[0][5] != 1 or header[2] != 0x3e:
            raise import_audit.AuditError(f"{path}: Linux libraries must be little-endian ELF64 x86-64 images")


def library_catalog(archive: Path, platform: str, archive_sha256: str, source=import_audit.PRX):
    if platform not in ("windows", "linux"):
        raise import_audit.AuditError(f"Unsupported library platform: {platform}")
    if not re.fullmatch(r"[a-f0-9]{64}", archive_sha256):
        raise import_audit.AuditError("Invalid library archive SHA-256")
    archive = Path(archive)
    digest = hashlib.sha256()
    with archive.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    if digest.hexdigest() != archive_sha256:
        raise import_audit.AuditError(f"{archive}: library archive SHA-256 mismatch")
    exports = {}
    libraries = []
    try:
        with zipfile.ZipFile(archive) as files:
            entries = files.infolist()
            if not entries or len(entries) > 4096:
                raise import_audit.AuditError(f"{archive}: invalid library archive entry count")
            seen = set()
            for entry in entries:
                name = entry.orig_filename
                parts = name.rstrip("/").split("/")
                mode = (entry.external_attr >> 16) & 0xf000
                invalid_parts = any(part in ("", ".", "..") or part.endswith((".", " ")) or re.fullmatch(r"(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part, re.IGNORECASE) for part in parts)
                if parts[0] != "libs" or len(parts) != (1 if entry.is_dir() else 2) or (entry.is_dir() and name != "libs/") or invalid_parts or "\\" in name or re.search(r'[\x00-\x1f<>:"|?*]', name) or mode not in (0, 0x8000, 0x4000) or entry.flag_bits & 1:
                    raise import_audit.AuditError(f"{archive}: invalid library archive layout: {name}")
                key = name.rstrip("/").casefold()
                if key in seen:
                    raise import_audit.AuditError(f"{archive}: duplicate library archive path: {entry.filename}")
                seen.add(key)
            corrupt = files.testzip()
            if corrupt:
                raise import_audit.AuditError(f"{archive}: corrupt library archive entry: {corrupt}")
            for entry in entries:
                if entry.is_dir() or not entry.filename.endswith(".prx"):
                    continue
                path = Path(entry.filename)
                data = files.read(entry)
                library_platform(path, data, platform)
                libraries.append(path.name)
                for name in import_audit.read_exports(path, data):
                    exports.setdefault(name, []).append(path.name)
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        raise import_audit.AuditError(f"{archive}: cannot read library archive: {error}") from error
    if not libraries:
        raise import_audit.AuditError(f"{archive}: no .prx libraries in the archive")
    source_stubs = []
    source_commit, source_dirty = None, None
    warnings = []
    if source is None:
        warnings.append("Throwing stub analysis is unavailable: no source tree was supplied.")
    else:
        source_commit, source_dirty = import_audit.git_stamp(source)
        try:
            source_stubs = [{"library": library, "nid": nid, "name": name} for (library, nid), name in sorted(import_audit.source_stubs(source).items())]
        except (import_audit.AuditError, OSError) as error:
            warnings.append(f"Throwing stub analysis is unavailable: {error}")
        if source_commit is None:
            warnings.append("The source commit is unknown; source findings cannot be tied to a revision.")
        if source_dirty:
            warnings.append("The source checkout contains uncommitted changes.")
    return {
        "schema": 1,
        "platform": platform,
        "archive_sha256": archive_sha256,
        "libraries": sorted(libraries),
        "exports": {name: sorted(providers) for name, providers in sorted(exports.items())},
        "source_stubs": source_stubs,
        "source_commit": source_commit,
        "source_dirty": source_dirty,
        "library_commit": None,
        "source_warnings": warnings,
    }
