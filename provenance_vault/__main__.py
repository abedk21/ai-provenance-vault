"""Demo and explicit sign/verify commands for a bounded local artifact set."""
import argparse
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from .core import VaultError, build_manifest, compare_manifests, sign_manifest, verify_manifest
from .report import render

# Used ONLY for explicitly labeled synthetic demo examples.
INSECURE_DEMO_KEY = b"INSECURE_DEMO_ONLY_NOT_A_SECRET_KEY_2026"


def demo(out: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="vault-demo-") as temp:
        root = Path(temp)
        (root / "model-card.md").write_text("Synthetic classifier v1; no real customer data.\n")
        (root / "metrics.json").write_text('{"f1":0.85,"synthetic":true}\n')
        ts = "2026-11-06T12:00:00Z"
        first = build_manifest(root,"sample-model","run-001",ts)
        att = sign_manifest(first,INSECURE_DEMO_KEY)
        policy={"max_files":8,"max_total_bytes":10000,"extensions":[".md",".json"]}
        good = verify_manifest(root,first,att,INSECURE_DEMO_KEY,policy=policy)
        (root / "metrics.json").write_text('{"f1":0.99,"synthetic":true}\n')
        tampered=verify_manifest(root,first,att,INSECURE_DEMO_KEY,policy=policy)
        (root / "metrics.json").write_text('{"f1":0.85,"synthetic":true}\n')
        (root / "model-card.md").write_text("Synthetic classifier v2; evaluation refreshed.\n")
        (root / "notes.txt").write_text("Offline, synthetic artifact update.\n")
        second=build_manifest(root,"sample-model","run-002",ts,parent_root=first['merkle_root'])
        lineage=compare_manifests(first,second)
        out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(render(good,tampered,lineage,first,second),encoding="utf-8")
        print(json.dumps({"report":str(out),"initial_verification":good,"after_tampering":tampered,"lineage":lineage},indent=2))


def secret_from_env() -> bytes:
    key=os.environ.get('VAULT_HMAC_KEY')
    if key is None:
        raise VaultError("Set VAULT_HMAC_KEY for create/verify; demo uses a labeled toy key")
    return key.encode('utf-8')


def main() -> None:
    p=argparse.ArgumentParser(description="Offline educational artifact attestations")
    subs=p.add_subparsers(dest="command",required=True)
    d=subs.add_parser("demo");d.add_argument("--out",type=Path,default=Path("examples/provenance_report.html"))
    c=subs.add_parser("create");c.add_argument("--root",type=Path,required=True);c.add_argument("--project",required=True);c.add_argument("--run-id",required=True);c.add_argument("--out",type=Path,required=True)
    v=subs.add_parser("verify");v.add_argument("--root",type=Path,required=True);v.add_argument("--manifest",type=Path,required=True);v.add_argument("--attestation",type=Path,required=True)
    a=p.parse_args()
    try:
        if a.command=="demo": demo(a.out);return
        key=secret_from_env()
        if a.command=="create":
            manifest=build_manifest(a.root,a.project,a.run_id,datetime.now(timezone.utc).isoformat())
            att=sign_manifest(manifest,key)
            a.out.mkdir(parents=True,exist_ok=True)
            (a.out/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
            (a.out/"attestation.json").write_text(json.dumps(att,indent=2)+"\n")
            print(json.dumps({"merkle_root":manifest['merkle_root'],"output":str(a.out)}))
        else:
            manifest=json.loads(a.manifest.read_text());att=json.loads(a.attestation.read_text())
            result=verify_manifest(a.root,manifest,att,key)
            print(json.dumps(result,indent=2))
            if not result['ok']: raise SystemExit(1)
    except VaultError as exc:
        p.error(str(exc))


if __name__=="__main__":main()
