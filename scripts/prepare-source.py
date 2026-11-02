#!/usr/bin/env python3
"""Assemble pinned upstream, integration patches and local additions offline."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(args, cwd):
    env = {key: value for key, value in os.environ.items()
           if key not in {'GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE'}}
    env['GIT_CEILING_DIRECTORIES'] = str(cwd.parent)
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"{' '.join(args)} failed:\n{result.stderr or result.stdout}")
    return result.stdout


def copy_upstream(source, destination):
    if not (source / 'go.mod').is_file() or not (source / 'main.go').is_file():
        raise RuntimeError('Upstream source missing; run git submodule update --init --recursive.')
    if (source / '.git').exists():
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


def overlay(source, destination):
    for entry in sorted(source.iterdir()):
        target = destination / entry.name
        if entry.is_dir() and not entry.is_symlink():
            if target.is_symlink() or (target.exists() and not target.is_dir()):
                raise RuntimeError(f'Overlay directory conflicts with upstream: {target}')
            target.mkdir(parents=True, exist_ok=True)
            overlay(entry, target)
        else:
            if target.exists() or target.is_symlink():
                raise RuntimeError(f'Our file now exists upstream: {target}; review the overlap.')
            shutil.copy2(entry, target, follow_symlinks=False)


def prepare(root=ROOT):
    root = Path(root).resolve()
    build = root / 'build'
    build.mkdir(exist_ok=True)
    output = build / 'mihomo'
    temporary = Path(tempfile.mkdtemp(prefix='.mihomo-', dir=build))
    previous = None
    try:
        copy_upstream(root / 'upstream/mihomo', temporary)
        for patch in sorted((root / 'patches').glob('*.patch')):
            run(['git', 'apply', '--no-index', '--check', str(patch)], temporary)
            run(['git', 'apply', '--no-index', str(patch)], temporary)
        overlay(root / 'src', temporary)
        overlay(root / 'docs', temporary / 'docs')
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
        return output
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
        if previous is not None:
            shutil.rmtree(previous)


if __name__ == '__main__':
    try:
        print(prepare())
    except (RuntimeError, OSError) as error:
        raise SystemExit(str(error))
