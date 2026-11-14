#!/usr/bin/env python3
"""Assemble pinned upstream, integration patches and local additions offline."""
import argparse
import fnmatch
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
IGNORED_NAMES = ('__pycache__', '*.pyc', '*~', '.*.swp')


def run(args, cwd):
    env = {key: value for key, value in os.environ.items()
           if key not in {'GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE'}}
    env['GIT_CEILING_DIRECTORIES'] = str(cwd.parent)
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"{' '.join(args)} failed:\n{result.stderr or result.stdout}")
    return result.stdout


def has_git(root):
    return (root / '.git').exists()


def staged_pin(root):
    """Return the upstream commit staged in the outer repository, if it has Git metadata."""
    if not has_git(root):
        return None
    entry = run(['git', 'ls-files', '--stage', '--', 'upstream/mihomo'], root).split()
    return entry[1] if entry and entry[0] == '160000' else None


def copy_upstream(source, destination, pin=None):
    if not (source / 'go.mod').is_file() or not (source / 'main.go').is_file():
        raise RuntimeError('Upstream source missing; run git submodule update --init --recursive.')
    if (source / '.git').exists():
        head = run(['git', 'rev-parse', 'HEAD'], source).strip()
        if pin is not None and head != pin:
            raise RuntimeError(
                f'upstream/mihomo is at {head}, but the outer repository pins {pin}. '
                'Run git submodule update, or stage a new pin with git add upstream/mihomo.')
        run(['git', 'diff', '--exit-code', 'HEAD', '--'], source)
        files = run(['git', 'ls-files', '-z'], source).split('\0')
        for filename in filter(None, files):
            target = destination / filename
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / filename, target, follow_symlinks=False)
    else:
        # Source archives and packaging tools may omit submodule Git metadata.
        shutil.copytree(source, destination, dirs_exist_ok=True, symlinks=True,
                        ignore=shutil.ignore_patterns('.git'))


def upstream_entries(source):
    """Return (relative path, stat) for upstream files, without following symlinks."""
    entries = []
    pending = [source]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as listing:
            for entry in listing:
                if entry.name == '.git':
                    continue
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                else:
                    entries.append((Path(entry.path).relative_to(source),
                                    entry.stat(follow_symlinks=False)))
    return sorted(entries, key=lambda item: item[0].as_posix())


def upstream_fingerprint(source, pin):
    """Validate the upstream checkout and return the stamp input describing it."""
    if not (source / 'go.mod').is_file() or not (source / 'main.go').is_file():
        raise RuntimeError('Upstream source missing; run git submodule update --init --recursive.')
    if (source / '.git').exists():
        head = run(['git', 'rev-parse', 'HEAD'], source).strip()
        if pin is not None and head != pin:
            raise RuntimeError(
                f'upstream/mihomo is at {head}, but the outer repository pins {pin}. '
                'Run git submodule update, or stage a new pin with git add upstream/mihomo.')
        run(['git', 'diff', '--exit-code', 'HEAD', '--'], source)
        return b'pin\0' + (pin or '').encode() + b'\0head\0' + head.encode()
    digest = hashlib.sha256()
    for relative, stat in upstream_entries(source):
        digest.update(relative.as_posix().encode())
        digest.update(b'\0')
        digest.update(str(stat.st_mtime_ns).encode())
        digest.update(b'\0')
        digest.update(str(stat.st_size).encode())
        digest.update(b'\n')
    return b'files\0' + digest.digest()


def ignored(name):
    return any(fnmatch.fnmatch(name, pattern) for pattern in IGNORED_NAMES)


def overlay_entries(source, paths):
    """Return (relative path, source path) pairs to overlay."""
    if paths is not None:
        return [(path, source / path) for path in paths]
    entries = []
    for entry in sorted(source.iterdir()):
        if ignored(entry.name):
            continue
        if entry.is_dir() and not entry.is_symlink():
            entries.extend((Path(entry.name) / relative, path)
                           for relative, path in overlay_entries(entry, None))
        else:
            entries.append((Path(entry.name), entry))
    return entries


def overlay_paths(root, name):
    """Return tracked paths to overlay, or None when the outer checkout has no Git metadata."""
    if not has_git(root):
        return None
    prefix = name + '/'
    files = run(['git', 'ls-files', '-z', '--', name], root).split('\0')
    paths = []
    for filename in files:
        if not filename.startswith(prefix):
            continue
        path = root / filename
        if path.exists() or path.is_symlink():
            paths.append(Path(filename[len(prefix):]))
    return sorted(paths)


def patch_files(root):
    """Return the patch files to apply, tracked by Git when the outer checkout has metadata."""
    if not has_git(root):
        return sorted((root / 'patches').glob('*.patch'))
    files = run(['git', 'ls-files', '-z', '--', 'patches'], root).split('\0')
    patches = []
    for filename in files:
        relative = Path(filename)
        path = root / relative
        if (relative.parent == Path('patches') and relative.name.endswith('.patch')
                and (path.exists() or path.is_symlink())):
            patches.append(path)
    return sorted(patches)


def add_content(digest, path):
    if path.is_symlink():
        digest.update(b'link\0')
        digest.update(os.readlink(path).encode())
    else:
        digest.update(b'content\0')
        digest.update(path.read_bytes())
    digest.update(b'\0')


def assembly_stamp(root):
    digest = hashlib.sha256()
    digest.update(b'upstream\0')
    digest.update(upstream_fingerprint(root / 'upstream/mihomo', staged_pin(root)))
    digest.update(b'\0')
    for patch in patch_files(root):
        digest.update(b'patch\0')
        digest.update(patch.relative_to(root).as_posix().encode())
        digest.update(b'\0')
        add_content(digest, patch)
    for name in ('src', 'docs'):
        for relative, path in overlay_entries(root / name, overlay_paths(root, name)):
            digest.update(b'overlay\0')
            digest.update(name.encode())
            digest.update(b'/')
            digest.update(relative.as_posix().encode())
            digest.update(b'\0')
            add_content(digest, path)
    digest.update(b'script\0')
    add_content(digest, Path(__file__).resolve())
    return digest.hexdigest()


def overlay(source, destination, paths=None):
    for relative, entry in overlay_entries(source, paths):
        target = destination / relative
        parent = destination
        for part in relative.parts[:-1]:
            parent = parent / part
            if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
                raise RuntimeError(f'Overlay directory conflicts with upstream: {parent}')
        if target.exists() or target.is_symlink():
            raise RuntimeError(f'Our file now exists upstream: {target}; review the overlap.')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(entry, target, follow_symlinks=False)


def prepare(root=ROOT, force=False):
    root = Path(root).resolve()
    build = root / 'build'
    build.mkdir(exist_ok=True)
    output = build / 'mihomo'
    stamp = build / '.mihomo.stamp'
    expected = assembly_stamp(root)
    if (not force and output.exists() and stamp.is_file()
            and stamp.read_text().strip() == expected):
        return output
    temporary = Path(tempfile.mkdtemp(prefix='.mihomo-', dir=build))
    previous = None
    try:
        copy_upstream(root / 'upstream/mihomo', temporary, staged_pin(root))
        for patch in patch_files(root):
            run(['git', 'apply', '--no-index', '--check', str(patch)], temporary)
            run(['git', 'apply', '--no-index', str(patch)], temporary)
        overlay(root / 'src', temporary, overlay_paths(root, 'src'))
        overlay(root / 'docs', temporary / 'docs', overlay_paths(root, 'docs'))
        # Keep the last good assembly when a patch or overlay fails.
        if output.exists():
            previous = Path(tempfile.mkdtemp(prefix='.previous-', dir=build))
            previous.rmdir()
            output.rename(previous)
        try:
            temporary.rename(output)
        except Exception:
            if previous is not None:
                previous.rename(output)
                previous = None
            raise
        stamp.write_text(expected + '\n')
        return output
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
        if previous is not None:
            shutil.rmtree(previous)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--force', action='store_true',
                        help='reassemble even when the stamp matches')
    arguments = parser.parse_args()
    try:
        print(prepare(force=arguments.force))
    except (RuntimeError, OSError) as error:
        raise SystemExit(str(error))


if __name__ == '__main__':
    main()
