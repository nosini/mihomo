"""Assembly protects the upstream pin and replaces generated files safely."""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location('prepare_source', ROOT / 'scripts/prepare-source.py')
assembler = module_from_spec(spec)
spec.loader.exec_module(assembler)


class AssemblyTests(unittest.TestCase):
    def setUp(self):
        (ROOT / 'build').mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT / 'build')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.upstream = self.root / 'upstream/mihomo'
        self.upstream.mkdir(parents=True)
        (self.upstream / 'main.go').write_text('package main\n')
        (self.upstream / 'go.mod').write_text('module example.invalid/fixture\n')
        (self.upstream / 'docs').mkdir()
        (self.upstream / 'docs/upstream.md').write_text('upstream\n')
        self.git('init', '-q')
        self.git('add', '.')
        # This synthetic fixture needs no SSH signing or user identity.
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                 '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture')
        for directory in ('src', 'patches', 'docs'):
            (self.root / directory).mkdir()
        (self.root / 'src/extra.go').write_text('package main\n// addition\n')
        (self.root / 'docs/local.md').write_text('local\n')
        (self.root / 'patches/0001-main.patch').write_text(
            'diff --git a/main.go b/main.go\n'
            '--- a/main.go\n+++ b/main.go\n@@ -1 +1 @@\n'
            '-package main\n+package patched\n')

    def git(self, *arguments):
        return subprocess.check_output(['git', *arguments], cwd=self.upstream,
                                       stderr=subprocess.STDOUT, text=True)

    def snapshot(self, root):
        return {str(p.relative_to(root)): p.read_bytes()
                for p in root.rglob('*') if p.is_file()}

    def test_assembly_leaves_upstream_and_outer_index_unchanged(self):
        index = Path(subprocess.check_output(
            ['git', 'rev-parse', '--git-path', 'index'], cwd=ROOT, text=True).strip())
        if not index.is_absolute():
            index = ROOT / index
        original_index = index.read_bytes()
        (self.upstream / 'untracked.go').write_text('must not be copied\n')
        output = assembler.prepare(self.root)
        self.assertEqual((output / 'main.go').read_text(), 'package patched\n')
        self.assertTrue((output / 'extra.go').is_file())
        self.assertTrue((output / 'docs/local.md').is_file())
        self.assertTrue((output / 'docs/upstream.md').is_file())
        self.assertFalse((output / 'untracked.go').exists())
        self.assertFalse((output / '.git').exists())
        self.assertEqual(self.git('status', '--porcelain', '--untracked-files=no'), '')
        self.assertEqual(index.read_bytes(), original_index)

    def test_deleted_addition_disappears_on_next_prepare(self):
        output = assembler.prepare(self.root)
        (self.root / 'src/extra.go').unlink()
        assembler.prepare(self.root)
        self.assertFalse((output / 'extra.go').exists())

    def test_failed_patch_preserves_last_good_assembly(self):
        output = assembler.prepare(self.root)
        before = self.snapshot(output)
        (self.root / 'patches/0001-main.patch').write_text('invalid patch\n')
        with self.assertRaises(RuntimeError):
            assembler.prepare(self.root)
        self.assertEqual(self.snapshot(output), before)
        self.assertEqual(sorted(p.name for p in (self.root / 'build').iterdir()), ['mihomo'])

    def test_upstream_collision_preserves_last_good_assembly(self):
        output = assembler.prepare(self.root)
        before = self.snapshot(output)
        (self.root / 'src/main.go').write_text('overlap\n')
        with self.assertRaisesRegex(RuntimeError, 'now exists upstream'):
            assembler.prepare(self.root)
        self.assertEqual(self.snapshot(output), before)

    def test_dirty_submodule_is_rejected(self):
        (self.upstream / 'main.go').write_text('unreviewed\n')
        with self.assertRaisesRegex(RuntimeError, 'diff --exit-code'):
            assembler.prepare(self.root)

    def test_archive_without_git_metadata_matches_checkout(self):
        output = assembler.prepare(self.root)
        expected = self.snapshot(output)
        shutil.rmtree(self.upstream / '.git')
        assembler.prepare(self.root)
        self.assertEqual(self.snapshot(output), expected)


if __name__ == '__main__':
    unittest.main()
