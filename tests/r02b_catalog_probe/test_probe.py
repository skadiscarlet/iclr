from __future__ import annotations
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("probe_module", ROOT / "tools" / "r02b_catalog_probe.py")
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.ws = self.base / "workspace"
        self.ws.mkdir()
        (self.ws / "metadata").mkdir()
        (self.ws / "metadata/r01_candidates.jsonl").write_text(json.dumps({"pair_id":"p1","local_catalog_key":"known-a"})+"\n")
        self.root = self.ws / "data"
        (self.root / "catalog").mkdir(parents=True)
        self.cat = self.root / "catalog/cases.jsonl"
        self.cat.write_text(json.dumps({"case_id":"known-a", "private_text":"DO_NOT_EXPORT"})+"\n")
    def test_regular_root(self):
        r=mod.probe(self.ws)
        self.assertTrue(r["catalog_complete"])
        self.assertEqual(r["candidate_matches"][0]["status"], "unique_match")
        self.assertNotIn("DO_NOT_EXPORT", json.dumps(r))
    def link_root(self):
        external=self.base / "shared_data"
        self.root.rename(external)
        self.root.symlink_to(external, target_is_directory=True)
    def test_root_symlink_requires_flag(self):
        self.link_root()
        with self.assertRaises(mod.ProbeError): mod.probe(self.ws)
    def test_explicit_root_symlink(self):
        self.link_root()
        r=mod.probe(self.ws, allow_root_symlink=True)
        self.assertTrue(r["catalog_complete"])
        self.assertTrue(r["root_symlink_observed"])
        self.assertNotIn(str(self.base), json.dumps(r))
    def test_nested_directory_symlink(self):
        folder=self.root / "catalog"
        other=self.base / "other"
        folder.rename(other)
        folder.symlink_to(other, target_is_directory=True)
        with self.assertRaises(mod.ProbeError): mod.probe(self.ws)
    def test_leaf_symlink(self):
        target=self.base / "original.jsonl"
        self.cat.rename(target)
        self.cat.symlink_to(target)
        with self.assertRaises(mod.ProbeError): mod.probe(self.ws)
    def test_partial_bytes_no_full_digest(self):
        r=mod.probe(self.ws,max_bytes=8)
        self.assertFalse(r["catalog_complete"])
        self.assertIsNone(r["catalog_sha256"])
        self.assertEqual(r["candidate_matches"][0]["status"],"partial_scan")
    def test_duplicate_matches(self):
        self.cat.write_text('{"id":"known-a"}\n{"id":"known-a"}\n')
        r=mod.probe(self.ws)
        self.assertEqual(r["candidate_matches"][0]["status"],"ambiguous_match")
    def test_invalid_json_retains_count(self):
        self.cat.write_text('not-json\n{"id":"known-a"}\n')
        r=mod.probe(self.ws)
        self.assertEqual(r["counts"]["invalid_json_rows"],1)
        self.assertTrue(r["catalog_complete"])
    def test_invalid_utf8(self):
        self.cat.write_bytes(b'\xff\n')
        self.assertEqual(mod.probe(self.ws)["counts"]["invalid_utf8_rows"],1)
    def test_non_object(self):
        self.cat.write_text('[]\n')
        self.assertEqual(mod.probe(self.ws)["counts"]["non_object_rows"],1)
    def test_record_limit(self):
        self.cat.write_text('{"id":"known-a"}\n{"id":"known-b"}\n')
        r=mod.probe(self.ws,max_records=1)
        self.assertFalse(r["catalog_complete"])
        self.assertEqual(r["stop_reason"],"record_limit")
    def test_output_guard(self):
        r=mod.probe(self.ws)
        with self.assertRaises(mod.ProbeError): mod.write_local(self.ws,"data/out.json",r)
        mod.write_local(self.ws,"artifacts/r02b/test.json",r)
        with self.assertRaises(mod.ProbeError): mod.write_local(self.ws,"artifacts/r02b/test.json",r)
    def test_no_newline_at_eof(self):
        self.cat.write_text('{"case_id":"known-a"}')
        self.assertTrue(mod.probe(self.ws)["catalog_complete"])
    def test_missing_key_is_not_zero_corpus(self):
        self.cat.write_text('{"nested":{"id":"known-a"}}\n')
        r=mod.probe(self.ws)
        self.assertEqual(r["counts"]["valid_object_rows"],1)
        self.assertEqual(r["candidate_matches"][0]["status"],"missing_match")
    def test_exact_size_limit_is_complete(self):
        n=self.cat.stat().st_size
        self.assertTrue(mod.probe(self.ws,max_bytes=n)["catalog_complete"])

if __name__=="__main__": unittest.main()
