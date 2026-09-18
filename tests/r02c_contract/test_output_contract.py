"""Pure synthetic unit tests. No torch, model calls or real repository corpus."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import sys
import unittest

MODULE_PATH = Path(__file__).resolve().parents[2] / "src/sbs/output_contract.py"
spec = importlib.util.spec_from_file_location("r02c_contract_standalone", MODULE_PATH)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)


def final(**overrides):
    result = dict(hypothesis="The declared identity requirement may fail.",
                  verdict="unresolved", support_refs=[], counter_refs=[],
                  unknowns=["The implementation is not supplied."], limitations=[])
    result.update(overrides)
    return result


def sbs(**overrides):
    result = dict(entities=["input", "return value"], requirement="Return the input unchanged.",
                  hypothesis="The identity requirement may fail.", support_refs=[],
                  counter_refs=[], unknowns=["Implementation unavailable."], limitations=[])
    result.update(overrides)
    return result


class OutputContractTests(unittest.TestCase):
    def parse(self, obj, kind="final"):
        return m.parse_response(json.dumps(obj), kind)

    def test_bare_final(self): self.assertTrue(self.parse(final()).accepted)
    def test_whitespace_only_normalization(self):
        raw = " \n" + json.dumps(final()) + "\n\t"
        r = m.parse_response(raw, "final")
        self.assertTrue(r.accepted)
        self.assertEqual(r.envelope, "bare")
    def test_json_fence(self):
        obj = final()
        r = m.parse_response("```json\n" + json.dumps(obj) + "\n```", "final")
        self.assertTrue(r.accepted)
        self.assertEqual(r.payload, obj)
        self.assertEqual(r.envelope, "whole_response_fence_removed")
    def test_plain_fence(self):
        self.assertTrue(m.parse_response("```\n" + json.dumps(final()) + "\n```", "final").accepted)
    def test_crlf_fence(self):
        self.assertTrue(m.parse_response("```json\r\n" + json.dumps(final()) + "\r\n```", "final").accepted)
    def test_single_line_fence_rejected(self):
        self.assertFalse(m.parse_response("```"+json.dumps(final())+"```", "final").accepted)
    def test_python_fence_rejected(self):
        self.assertFalse(m.parse_response("```python\n"+json.dumps(final())+"\n```", "final").accepted)
    def test_prose_prefix_rejected(self):
        self.assertFalse(m.parse_response("Here is the answer:\n"+json.dumps(final()), "final").accepted)
    def test_prose_suffix_rejected(self):
        self.assertFalse(m.parse_response(json.dumps(final())+"\nExplanation", "final").accepted)
    def test_two_objects_rejected(self):
        self.assertFalse(m.parse_response(json.dumps(final())*2, "final").accepted)
    def test_two_fences_rejected(self):
        raw = "```json\n"+json.dumps(final())+"\n```\n```json\n"+json.dumps(final())+"\n```"
        self.assertFalse(m.parse_response(raw, "final").accepted)
    def test_truncation_not_completed(self):
        self.assertFalse(m.parse_response(json.dumps(final())[:-1], "final").accepted)
    def test_true_string_never_relabelled(self):
        r = self.parse(final(verdict="True"))
        self.assertFalse(r.accepted)
        self.assertEqual(r.payload["verdict"], "True")
        self.assertIn("invalid_verdict_enum", r.error_codes)
    def test_boolean_never_relabelled(self): self.assertFalse(self.parse(final(verdict=True)).accepted)
    def test_numeric_verdict_rejected(self): self.assertFalse(self.parse(final(verdict=1)).accepted)
    def test_all_legal_verdicts(self):
        for verdict in ("supported", "refuted", "unresolved"):
            with self.subTest(verdict=verdict): self.assertTrue(self.parse(final(verdict=verdict)).accepted)
    def test_case_sensitive_enum(self): self.assertFalse(self.parse(final(verdict="Supported")).accepted)
    def test_missing_array_not_defaulted(self):
        obj = final(); del obj["limitations"]
        r=self.parse(obj)
        self.assertFalse(r.accepted)
        self.assertNotIn("limitations",r.payload)
    def test_extra_field_rejected(self): self.assertFalse(self.parse(final(extra="x")).accepted)
    def test_refs_string_not_list(self): self.assertFalse(self.parse(final(support_refs="ev-1")).accepted)
    def test_refs_dict_not_coerced(self):
        self.assertFalse(self.parse(final(support_refs=[{"evidence_id":"ev-1"}])).accepted)
    def test_refs_mixed_types(self): self.assertFalse(self.parse(final(counter_refs=[1])).accepted)
    def test_duplicate_reference(self): self.assertFalse(self.parse(final(support_refs=["ev-1","ev-1"])).accepted)
    def test_empty_hypothesis(self): self.assertFalse(self.parse(final(hypothesis=" ")).accepted)
    def test_duplicate_key_rejected(self):
        raw = json.dumps(final())[:-1] + ', "verdict":"supported"}'
        self.assertIn("duplicate_json_key",m.parse_response(raw,"final").error_codes)
    def test_nan_rejected(self):
        self.assertIn("nonfinite_json_number",self.parse(final(verdict=float("nan"))).error_codes)
    def test_inf_rejected(self):
        self.assertIn("nonfinite_json_number",self.parse(final(verdict=float("inf"))).error_codes)
    def test_top_array_rejected(self): self.assertFalse(self.parse([final()]).accepted)
    def test_null_rejected(self): self.assertFalse(self.parse(None).accepted)
    def test_history_note(self): self.assertTrue(self.parse({"note":"A functional relation remains unknown."},"history_note").accepted)
    def test_history_no_extra_verdict(self):
        self.assertFalse(self.parse({"note":"x","verdict":"unresolved"},"history_note").accepted)
    def test_sbs_note(self): self.assertTrue(self.parse(sbs(),"sbs_note").accepted)
    def test_sbs_entities_type(self): self.assertFalse(self.parse(sbs(entities="input"),"sbs_note").accepted)
    def test_sbs_missing_requirements(self):
        obj=sbs(); del obj["requirement"]
        self.assertFalse(self.parse(obj,"sbs_note").accepted)
    def test_sbs_note_has_no_forced_verdict(self):
        self.assertFalse(self.parse(sbs(verdict="unresolved"),"sbs_note").accepted)
    def test_binding_checks_unobserved_id(self):
        obj=final(support_refs=["ev-1"])
        self.assertEqual(m.reference_id_errors(obj,{"ev-1"}),())
        self.assertTrue(m.reference_id_errors(obj,set()))
        self.assertEqual(obj["support_refs"],["ev-1"])
    def test_schema_is_not_support_sufficiency(self):
        # Shape accepted: the production semantic/claim admissibility layer must
        # separately reject an asserted conclusion lacking an evidence witness.
        self.assertTrue(self.parse(final(verdict="supported",support_refs=[])).accepted)
    def test_public_summary_has_no_prose(self):
        r=self.parse(final(hypothesis="PRIVATE-CANARY"))
        self.assertNotIn("PRIVATE-CANARY",json.dumps(r.public_summary()))
    def test_raw_size_limit(self):
        self.assertIn("raw_too_large",m.parse_response("x"*65537,"final").error_codes)
    def test_unicode_content_preserved(self):
        obj=final(hypothesis="输入与返回值的关系尚不明确。")
        self.assertEqual(self.parse(obj).payload,obj)
    def test_raw_hash_stable_across_parsers(self):
        raw=json.dumps(final())
        self.assertEqual(m.parse_response(raw,"final").raw_sha256,m.parse_response(raw,"sbs_note").raw_sha256)
    def test_unknown_contract_fails(self):
        with self.assertRaises(ValueError): m.parse_response("{}","bogus")
    def test_wrong_raw_type_fails(self):
        with self.assertRaises(TypeError): m.parse_response({},"final")

if __name__ == "__main__": unittest.main()
