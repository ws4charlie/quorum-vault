#!/usr/bin/env python3
"""Tests of the two Nitro helper scripts (no AWS, no network). Run by deploy/cloud/aws/check.sh, step nitro."""
import importlib.util, json, os, unittest
from datetime import datetime, timezone

here = os.path.dirname(os.path.abspath(__file__))


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, os.path.join(here, file))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


cli, tfv = load("cli", "nitro-cli-to-allowlist.py"), load("tfv", "allowlist-to-tfvars.py")
H = lambda c: c * 96
NOW = datetime(2026, 12, 1, tzinfo=timezone.utc)
# what `nitro-cli build-enclave` prints: progress lines, then the JSON. The values are those of a stand-in image built to test the tool (docs/runbooks/nitro-first-run.md).
OUT = """Start building the Enclave Image...
Using the locally available Docker image...
Enclave Image successfully created.
{
  "Measurements": {
    "HashAlgorithm": "Sha384 { ... }",
    "PCR0": "%s", "PCR1": "%s", "PCR2": "%s"
  }
}
""" % (H("a"), H("b"), H("c"))


class CliToAllowlist(unittest.TestCase):
    def test_command(self):
        c = cli.command("A", "v1.4.0", cli.pcrs(cli.extract(OUT)))
        self.assertEqual(c, "qv-attest-broker allowlist add -in current.json -out next.json -party A -measurement %s -version v1.4.0 -pcr 1=%s -pcr 2=%s" % (H("a"), H("b"), H("c")))

    def test_pcr8_when_signed(self):
        p = cli.pcrs(cli.extract(OUT.replace('"PCR2"', '"PCR8": "%s", "PCR2"' % H("d"))))
        self.assertIn("-pcr 8=" + H("d"), cli.command("A", "v1", p))

    def test_refusals(self):
        for bad in [OUT.replace(H("a"), H("0")), OUT.replace(H("b"), "abc"), OUT.replace('"PCR0"', '"PCR9"'), "no json here", '{"x": 1}',
                    OUT.replace(H("a"), "a" * 95 + "g")]:
            with self.assertRaises(ValueError, msg=bad[:60]):
                cli.pcrs(cli.extract(bad))
        with self.assertRaises(ValueError):
            cli.command("A B", "v1", {0: H("a")})
        with self.assertRaises(ValueError):
            cli.command("A", "v 1", {0: H("a")})


def lst(entries, sigs=True):
    return {"seq": 3, "signed_at": 1, "entries": entries, "signatures": [{"operator": "alice", "signature": "00"}] if sigs else []}


def entry(party="A", m=None, ver="v1", nb="2026-01-01T00:00:00Z", na=None, status=None, pcrs=None):
    e = {"party": party, "measurement": m or H("a"), "not_before": nb, "version": ver}
    if na:
        e["not_after"] = na
    if status:
        e["status"] = status
    if pcrs:
        e["pcrs"] = pcrs
    return e


class AllowlistToTfvars(unittest.TestCase):
    def test_nitro_entry_becomes_an_image_with_every_pcr(self):
        out, w = tfv.build(lst([entry(pcrs={"1": H("b"), "2": H("C"), "8": H("d")})]), "A", NOW)
        self.assertEqual(out, {"allowed_images": [{"name": "v1", "pcrs": {"0": H("a"), "1": H("b"), "2": H("c"), "8": H("d")}}]})
        self.assertEqual(w, [])

    def test_only_this_party(self):
        out, _ = tfv.build(lst([entry("B", H("e")), entry("A", H("a"))]), "A", NOW)
        self.assertEqual([i["pcrs"]["0"] for i in out["allowed_images"]], [H("a")])

    def test_overlap_gives_two_images(self):
        out, _ = tfv.build(lst([entry(ver="v1"), entry(m=H("e"), ver="v2")]), "A", NOW)
        self.assertEqual([i["name"] for i in out["allowed_images"]], ["v1", "v2"])

    def test_revoked_removes_every_entry_of_that_image(self):
        out, _ = tfv.build(lst([entry(ver="v1"), entry(m=H("e"), ver="v2"), entry(status="revoked", ver="v1")]), "A", NOW)
        self.assertEqual([i["name"] for i in out["allowed_images"]], ["v2"])

    def test_window(self):
        out, _ = tfv.build(lst([entry(ver="old", na="2026-11-01T00:00:00Z"), entry(m=H("e"), ver="future", nb="2027-01-01T00:00:00Z"), entry(m=H("f"), ver="now")]), "A", NOW)
        self.assertEqual([i["name"] for i in out["allowed_images"]], ["now"])

    def test_nothing_active_is_an_error_never_an_empty_policy(self):
        for l in (lst([]), lst([entry("B")]), lst([entry(status="revoked")]), lst([entry(na="2026-11-01T00:00:00Z")])):
            with self.assertRaises(ValueError):
                tfv.build(l, "A", NOW)

    def test_unsigned_list_is_refused(self):
        with self.assertRaises(ValueError):
            tfv.build(lst([entry()], sigs=False), "A", NOW)

    def test_bad_values_are_refused(self):
        for e in (entry(m=H("0")), entry(m="abc"), entry(pcrs={"1": H("0")}), entry(pcrs={"1": "xyz"})):
            with self.assertRaises(ValueError):
                tfv.build(lst([e]), "A", NOW)

    def test_pcr0_only_warns(self):
        _, w = tfv.build(lst([entry()]), "A", NOW)
        self.assertEqual(len(w), 1)

    def test_duplicate_names_are_refused(self):
        with self.assertRaises(ValueError):
            tfv.build(lst([entry(ver="v1"), entry(m=H("e"), ver="v1")]), "A", NOW)

    def test_the_output_is_what_the_module_validates(self):
        # the module's rule (variables.tf): PCR number 0..99, 96 lower-case hex, not all zero, PCR0 present
        out, _ = tfv.build(lst([entry(pcrs={"1": H("b"), "8": H("D")})]), "A", NOW)
        for i in out["allowed_images"]:
            self.assertIn("0", i["pcrs"])
            for k, v in i["pcrs"].items():
                self.assertTrue(k.isdigit() and 0 <= int(k) < 100)
                self.assertRegex(v, r"^[0-9a-f]{96}$")


if __name__ == "__main__":
    unittest.main(verbosity=1)
