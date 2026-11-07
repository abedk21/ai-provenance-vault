import copy
import json
import tempfile
import unittest
from pathlib import Path
from provenance_vault.core import (VaultError, build_manifest, canonical, compare_manifests,
    merkle_root, policy_issues, sha_file, sign_manifest, valid_relpath, verify_manifest, walk_files)
from provenance_vault.report import render

KEY=b'synthetic-test-key-please-do-not-reuse'
TIME='2026-11-06T12:00:00Z'
POLICY={'extensions':['.txt','.json'],'max_files':8,'max_total_bytes':3000}


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        (self.root/'a.txt').write_text('alpha\n')
        (self.root/'b.json').write_text('{"synthetic":true}\n')
        self.manifest=build_manifest(self.root,'sample','r1',TIME)
        self.att=sign_manifest(self.manifest,KEY)
    def verify(self,**kw):return verify_manifest(self.root,self.manifest,self.att,KEY,**kw)
    def test_initial_good(self): self.assertTrue(self.verify()['ok'])
    def test_hash_size(self): self.assertEqual(len(self.manifest['merkle_root']),64)
    def test_canonical_stable(self): self.assertEqual(canonical({'b':1,'a':2}),canonical({'a':2,'b':1}))
    def test_merkle_deterministic(self): self.assertEqual(merkle_root(self.manifest['files']),self.manifest['merkle_root'])
    def test_sha_file(self): self.assertEqual(sha_file(self.root/'a.txt'),self.manifest['files'][0]['sha256'])
    def test_sign_deterministic(self): self.assertEqual(sign_manifest(self.manifest,KEY),self.att)
    def test_key_not_in_attestation(self): self.assertNotIn(KEY.decode(),json.dumps(self.att))
    def test_modified_file(self):
        (self.root/'a.txt').write_text('tamper')
        self.assertIn('sha_mismatch:a.txt',self.verify()['issues'])
    def test_missing_file(self):
        (self.root/'a.txt').unlink()
        self.assertIn('missing_files',self.verify()['issues'])
    def test_extra_file_detected(self):
        (self.root/'extra.txt').write_text('extra')
        self.assertIn('unexpected_files',self.verify()['issues'])
    def test_extra_file_allowed(self):
        (self.root/'extra.txt').write_text('extra')
        self.assertTrue(self.verify(strict_extra=False)['ok'])
    def test_wrong_key(self):
        self.assertIn('signature_mismatch',verify_manifest(self.root,self.manifest,self.att,b'another-secret-please-do-not-reuse')['issues'])
    def test_changed_manifest_detected(self):
        other=copy.deepcopy(self.manifest);other['project']='injected'
        r=verify_manifest(self.root,other,self.att,KEY)
        self.assertIn('signature_mismatch',r['issues']);self.assertIn('manifest_digest_mismatch',r['issues'])
    def test_changed_root_detected(self):
        other=copy.deepcopy(self.manifest);other['merkle_root']='0'*64
        self.assertIn('merkle_root_mismatch',verify_manifest(self.root,other,self.att,KEY)['issues'])
    def test_wrong_attestation_scheme(self):
        other=copy.deepcopy(self.att);other['scheme']='magic'
        self.assertIn('unknown_attestation_scheme',verify_manifest(self.root,self.manifest,other,KEY)['issues'])
    def test_missing_signature(self):
        other=copy.deepcopy(self.att);del other['signature']
        self.assertIn('signature_mismatch',verify_manifest(self.root,self.manifest,other,KEY)['issues'])
    def test_policy_pass(self): self.assertEqual(policy_issues(self.manifest,POLICY),[])
    def test_policy_file_count(self): self.assertIn('policy_file_count',policy_issues(self.manifest,{'max_files':1}))
    def test_policy_total_bytes(self): self.assertIn('policy_total_bytes',policy_issues(self.manifest,{'max_total_bytes':1}))
    def test_policy_extensions(self): self.assertIn('policy_extension',policy_issues(self.manifest,{'extensions':['.txt']}))
    def test_policy_enforced(self): self.assertFalse(self.verify(policy={'max_files':0})['ok'])
    def test_invalid_policy(self):
        with self.assertRaises(VaultError):policy_issues(self.manifest,{'max_files':-1})
    def test_bad_secret(self):
        with self.assertRaises(VaultError):sign_manifest(self.manifest,b'x')
    def test_bad_label(self):
        with self.assertRaises(VaultError):build_manifest(self.root,'../wrong','r1',TIME)
    def test_bad_timestamp(self):
        with self.assertRaises(VaultError):build_manifest(self.root,'sample','r1','2026-11-06')
    def test_bad_parent(self):
        with self.assertRaises(VaultError):build_manifest(self.root,'sample','r2',TIME,parent_root='oops')
    def test_path_traversal(self):
        bad=copy.deepcopy(self.manifest);bad['files'][0]['path']='../escape.txt'
        with self.assertRaises(VaultError):verify_manifest(self.root,bad,self.att,KEY)
    def test_absolute_path(self): self.assertFalse(valid_relpath('/etc/passwd'))
    def test_double_separator(self): self.assertFalse(valid_relpath('x//y'))
    def test_backslash_path(self): self.assertFalse(valid_relpath('..\\evil'))
    def test_symlink_denied(self):
        (self.root/'link.txt').symlink_to(self.root/'a.txt')
        self.assertIn('unsafe_file_or_symlink',self.verify()['issues'])
    def test_symlink_at_capture_denied(self):
        (self.root/'link.txt').symlink_to(self.root/'a.txt')
        with self.assertRaises(VaultError):build_manifest(self.root,'sample','r2',TIME)
    def test_empty_tree_denied(self):
        for path in self.root.iterdir():path.unlink()
        with self.assertRaises(VaultError):build_manifest(self.root,'sample','r2',TIME)
    def test_lineage(self):
        (self.root/'a.txt').write_text('beta')
        (self.root/'c.txt').write_text('more')
        second=build_manifest(self.root,'sample','r2',TIME,parent_root=self.manifest['merkle_root'])
        diff=compare_manifests(self.manifest,second)
        self.assertEqual(diff['added'],['c.txt']);self.assertEqual(diff['modified'],['a.txt'])
    def test_lineage_wrong_parent(self):
        second=build_manifest(self.root,'sample','r2',TIME)
        with self.assertRaises(VaultError):compare_manifests(self.manifest,second)
    def test_unordered_file_list(self):
        with self.assertRaises(VaultError):merkle_root(list(reversed(self.manifest['files'])))
    def test_html(self):
        (self.root/'a.txt').write_text('changed')
        tampered=self.verify()
        (self.root/'a.txt').write_text('alpha\n')
        (self.root/'a.txt').write_text('new')
        second=build_manifest(self.root,'sample','r2',TIME,parent_root=self.manifest['merkle_root'])
        h=render({'ok':True,'file_count':2},tampered,compare_manifests(self.manifest,second),self.manifest,second)
        self.assertIn('Build lineage',h);self.assertIn('sha_mismatch',h)
    def test_fixture_data(self):
        sample=Path(__file__).resolve().parents[1]/'fixtures'/'sample_data'
        self.assertTrue(build_manifest(sample,'fixture','run1',TIME)['files'])

if __name__=='__main__':unittest.main()
