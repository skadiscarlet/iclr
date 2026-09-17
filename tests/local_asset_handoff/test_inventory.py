from __future__ import annotations
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[2]
SRC = PROJECT / 'src'
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
spec = importlib.util.spec_from_file_location('asset_handoff', PROJECT / 'tools/local_asset_handoff.py')
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / 'repo'
        self.root.mkdir()
        (self.root / 'data').mkdir()
        self.out = self.root / 'artifacts/local_asset_scan/test'

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    def scan(self, **kw):
        return module.scan(self.root, ['data', 'artifacts'], self.out, **kw)

    def rows(self):
        return [json.loads(line) for line in (self.out / 'file_inventory.jsonl').read_text().splitlines()]

    def test_inventory_does_not_export_contents_or_absolute_root(self):
        self.write('data/example.txt', 'UNIQUE_RAW_CONTENT_NOT_FOR_EXPORT')
        self.scan()
        exported = ''.join(p.read_text() for p in self.out.iterdir())
        self.assertNotIn('UNIQUE_RAW_CONTENT_NOT_FOR_EXPORT', exported)
        self.assertNotIn(str(self.root), exported)
        self.assertEqual(len(self.rows()), 1)

    def test_content_hash_is_actual_bytes(self):
        self.write('data/a.txt', 'abc')
        self.scan()
        row = self.rows()[0]
        self.assertEqual(row['content_sha256'], 'sha256:' + hashlib.sha256(b'abc').hexdigest())
        self.assertEqual(row['hash_status'], 'complete')

    def test_profile_exports_schema_and_allowed_enums_only(self):
        self.write('data/catalog.jsonl', json.dumps({'id':'PRIVATE_SAMPLE_VALUE','status':'source_resolved','split':'dev_pilot','details':{'text':'DO_NOT_COPY'}}) + '\n')
        self.scan(profiles=['data/catalog.jsonl'])
        text = (self.out / 'profiles.json').read_text()
        self.assertNotIn('PRIVATE_SAMPLE_VALUE', text)
        self.assertNotIn('DO_NOT_COPY', text)
        p = json.loads(text)[0]
        self.assertEqual(p['scanned_records'], 1)
        self.assertTrue(p['complete'])
        self.assertEqual(p['allowed_enum_distributions']['status']['source_resolved'], 1)

    def test_sensitive_files_are_not_listed_or_profiled(self):
        self.write('data/.env', 'SECRET_VALUE')
        self.write('data/private_key.pem', 'SECRET_KEY_VALUE')
        summary = self.scan(profiles=['data/.env'])
        self.assertEqual(summary['excluded_sensitive_entries'], 2)
        self.assertEqual(self.rows(), [])
        p = json.loads((self.out / 'profiles.json').read_text())[0]
        self.assertEqual(p['status'], 'excluded_sensitive')
        self.assertIsNone(p['relative_path'])
        self.assertNotIn('SECRET_VALUE', (self.out / 'profiles.json').read_text())

    def test_symlink_outside_not_followed(self):
        external = Path(self.tmp.name) / 'outside.txt'
        external.write_text('OUTSIDE_VALUE')
        (self.root / 'data/link.txt').symlink_to(external)
        result = self.scan(profiles=['data/link.txt'])
        self.assertEqual(result['symlinks_not_followed'], 1)
        self.assertEqual(self.rows(), [])
        profile = json.loads((self.out / 'profiles.json').read_text())[0]
        self.assertEqual(profile['status'], 'symlink_not_followed')
        self.assertIsNone(profile['scanned_records'])
        self.assertFalse(profile['complete'])

    def test_symlink_root_is_not_empty_verified_dataset(self):
        external = Path(self.tmp.name) / 'outside_data'
        external.mkdir()
        (external / 'secret.jsonl').write_text('{}\n')
        data = self.root / 'data'
        shutil.rmtree(data)
        data.symlink_to(external)
        result = self.scan(profiles=['data/secret.jsonl'])
        roots = {row['root']: row for row in result['roots']}
        self.assertEqual(roots['data']['status'], 'symlink_not_followed')
        self.assertIsNone(roots['data']['files_observed'])
        self.assertFalse(result['listing_complete_within_declared_scope'])
        profile = json.loads((self.out / 'profiles.json').read_text())[0]
        self.assertEqual(profile['status'], 'symlink_not_followed')
        self.assertIsNone(profile['scanned_records'])
        self.assertNotEqual(profile['status'], 'complete')

    def test_published_handoff_rejects_template_and_absolute_home(self):
        with self.assertRaises(ValueError):
            module.assert_publication_safe('status: TEMPLATE_NOT_EXECUTED')
        with self.assertRaises(ValueError):
            module.assert_publication_safe('collected under /home/someone/project')
        module.assert_publication_safe('remote_visibility=summary_only; content_not_remotely_reviewed')
        tmp = self.root / 'reports'
        tmp.mkdir()
        (tmp / 'SUMMARY.json').write_text(json.dumps({
            'document_kind': 'template_not_results',
            'scan_status': 'not_started',
            'collection_code_sha': None,
        }))
        with self.assertRaises(ValueError):
            module.load_published_summary(tmp / 'SUMMARY.json')
        (tmp / 'index.jsonl').write_text(
            json.dumps({'document_kind': 'template_not_results', 'asset_id': None}) + '\n'
        )
        with self.assertRaises(ValueError):
            module.load_published_index(tmp / 'index.jsonl')
        (tmp / 'ok.json').write_text(json.dumps({
            'document_kind': 'local_asset_summary',
            'scan_status': 'partial',
            'collection_code_sha': 'abc',
            'scan_complete': False,
        }))
        loaded = module.load_published_summary(tmp / 'ok.json')
        self.assertEqual(loaded['scan_complete'], False)
        published_summary = PROJECT / 'reports/local_assets/SUMMARY.json'
        published_index = PROJECT / 'reports/local_assets/index.jsonl'
        if published_summary.is_file():
            payload = module.load_published_summary(published_summary)
            self.assertNotEqual(payload.get('document_kind'), 'template_not_results')
            self.assertIs(payload.get('scan_complete'), False)
        if published_index.is_file():
            rows = module.load_published_index(published_index)
            self.assertTrue(rows)
            self.assertTrue(all(row.get('document_kind') != 'template_not_results' for row in rows))

    def test_relative_path_escape_rejected(self):
        result = module.profile_file(self.root, '../outside.json', 100, 10)
        self.assertEqual(result['status'], 'relative_path_required')
        with self.assertRaises(ValueError):
            module.scan(self.root, ['data'], self.root / 'data/output')

    def test_file_limit_reports_partial(self):
        for i in range(3): self.write(f'data/{i}.txt', str(i))
        result = self.scan(max_files=1)
        self.assertEqual(result['files_observed'], 1)
        self.assertTrue(result['file_budget_hit'])
        self.assertFalse(result['listing_complete_within_declared_scope'])

    def test_hash_budget_does_not_fake_hash(self):
        self.write('data/a.txt', 'abc')
        self.write('data/b.txt', 'defg')
        result = self.scan(max_hash_bytes=3)
        self.assertEqual(result['bytes_hashed'], 3)
        rows = self.rows()
        self.assertEqual(rows[1]['hash_status'], 'skipped_total_hash_budget')
        self.assertIsNone(rows[1]['content_sha256'])

    def test_binary_is_metadata_only(self):
        self.write('data/model.gguf', 'FAKE_BINARY_FOR_UNIT_TEST_ONLY')
        self.scan()
        self.assertEqual(self.rows()[0]['hash_status'], 'skipped_binary_or_archive')
        self.assertIsNone(self.rows()[0]['content_sha256'])

    def test_invalid_jsonl_preserves_error_count(self):
        self.write('data/catalog.jsonl', '{"status":"source_resolved"}\nNOT_JSON_PRIVATE_TEXT\n{"status":"excluded"}\n')
        p = module.profile_file(self.root, 'data/catalog.jsonl', 4096, 10)
        self.assertEqual(p['scanned_records'], 2)
        self.assertEqual(p['invalid_units'], 1)
        self.assertEqual(p['status'], 'complete_with_invalid_rows')
        self.assertNotIn('NOT_JSON_PRIVATE_TEXT', json.dumps(p))

    def test_profile_limit_is_not_full_count(self):
        self.write('data/catalog.jsonl', '{}\n{}\n{}\n')
        p = module.profile_file(self.root, 'data/catalog.jsonl', 4096, 1)
        self.assertEqual(p['scanned_records'], 1)
        self.assertFalse(p['complete'])
        self.assertEqual(p['status'], 'prefix_only')

    def test_missing_is_not_zero_verified_records(self):
        p = module.profile_file(self.root, 'data/missing.jsonl', 4096, 10)
        self.assertEqual(p['status'], 'missing')
        self.assertIsNone(p['scanned_records'])

    def test_own_scan_output_not_recursively_inventoried(self):
        self.write('data/a.txt', 'x')
        first = self.scan()
        second = self.scan()
        self.assertEqual(first['files_observed'], second['files_observed'])
        self.assertEqual(second['files_observed'], 1)

    def test_csv_arbitrary_enum_value_not_exported(self):
        self.write('data/table.csv', 'status,split,notes\nsource_resolved,dev_pilot,HIDDEN_NOTES\nPRIVATE_VALUE,test,HIDDEN_AGAIN\n')
        p = module.profile_file(self.root, 'data/table.csv', 4096, 10)
        self.assertEqual(p['scanned_records'], 2)
        self.assertEqual(p['allowed_enum_distributions']['status']['<other>'], 1)
        self.assertNotIn('PRIVATE_VALUE', json.dumps(p))
        self.assertNotIn('HIDDEN_NOTES', json.dumps(p))

    @unittest.skipUnless(shutil.which('git'), 'git not present')
    def test_tracked_ignored_and_untracked_distinguished(self):
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.write('.gitignore', 'data/ignored.json\nartifacts/\n')
        self.write('data/tracked.json', '{}')
        self.write('data/ignored.json', '{}')
        self.write('data/untracked.json', '{}')
        subprocess.run(['git', '-C', str(self.root), 'add', 'data/tracked.json'], check=True)
        self.scan()
        states = {r['relative_path']:r['git_state'] for r in self.rows()}
        self.assertEqual(states['data/tracked.json'], 'tracked')
        self.assertEqual(states['data/ignored.json'], 'ignored')
        self.assertEqual(states['data/untracked.json'], 'untracked')

    def test_unsafe_schema_key_redacted(self):
        self.write('data/object.json', json.dumps({'/private/home/name':'DO_NOT_EXPORT'}))
        p = module.profile_file(self.root, 'data/object.json', 4096, 10)
        self.assertNotIn('/private/home/name', json.dumps(p))
        self.assertIn('<redacted_key>', json.dumps(p))


class CrossCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            'asset_xcheck', PROJECT / 'tools/local_asset_xcheck.py'
        )
        assert spec is not None and spec.loader is not None
        cls.xcheck = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.xcheck)

    def test_cross_check_recomputes_shipped_counts_and_ready_actor_files(self):
        result = self.xcheck.run_cross_checks(
            PROJECT,
            summary_path=(PROJECT / 'reports/local_assets/SUMMARY.json')
            if (PROJECT / 'reports/local_assets/SUMMARY.json').is_file() else None,
            index_path=(PROJECT / 'reports/local_assets/index.jsonl')
            if (PROJECT / 'reports/local_assets/index.jsonl').is_file() else None,
        )
        inv = result['inventory']
        from sbs.registry import count_inventory, human_verified_count, load_candidates, load_readiness
        candidates = load_candidates(PROJECT / 'metadata/r01_candidates.jsonl')
        readiness = load_readiness(PROJECT / 'metadata/r01_readiness.csv')
        fixture_ids = sorted(
            p.name for p in (PROJECT / 'fixtures/r01').iterdir() if p.is_dir()
        )
        expected = count_inventory(candidates, readiness, fixture_ids)
        self.assertEqual(inv['candidate_pairs'], expected['candidate_pairs'])
        self.assertEqual(inv['real_ready_pairs'], expected['real_ready_pairs'])
        self.assertEqual(inv['human_verified_pairs'], expected['human_verified_pairs'])
        self.assertEqual(inv['human_verified_pairs'], human_verified_count(candidates))
        self.assertEqual(inv['human_verified_pairs'], 0)
        self.assertEqual(inv['fixture_cases'], expected['fixture_cases'])
        self.assertEqual(
            inv['real_ready_pairs'],
            sum(1 for row in readiness if row['ready'] == 'yes'),
        )
        self.assertEqual(inv['ready_pair_ids'], [row['pair_id'] for row in readiness if row['ready'] == 'yes'])
        ids = {row['check_id'] for row in result['checks']}
        self.assertEqual(ids, {'X01', 'X02', 'X03', 'X04', 'X05', 'X06', 'X07', 'X08'})
        self.assertFalse(result['failed'])
        x02 = next(row for row in result['checks'] if row['check_id'] == 'X02')
        actor_root = PROJECT / 'local_data/r01/actor'
        if actor_root.is_dir():
            self.assertEqual(x02['status'], 'passed')
            for pair_id in inv['ready_pair_ids']:
                case = json.loads((actor_root / pair_id / 'case.json').read_text())
                self.assertTrue(set(case).isdisjoint({'cve', 'gold_label', 'patch', 'fix_pairing', 'gold'}))
                self.assertFalse((actor_root / pair_id / 'answers.json').exists())
        published = PROJECT / 'reports/local_assets/SUMMARY.json'
        if published.is_file():
            summary = json.loads(published.read_text())
            counts = summary.get('counts', summary)
            self.assertEqual(counts['candidate_pairs'], expected['candidate_pairs'])
            self.assertEqual(counts['real_ready_pairs'], expected['real_ready_pairs'])
            self.assertEqual(counts['human_verified_pairs'], 0)
            self.assertIs(summary.get('scan_complete'), False)


if __name__ == '__main__':
    unittest.main()
