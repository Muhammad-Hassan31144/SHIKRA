#!/usr/bin/env python3
"""
Agent simulator for Shikra Host (Shost)

Use this to test the post-upload flow: authenticate, get next sample, and download it.

Auth scheme now uses Bearer token:
    Headers: X-Agent-ID: <agent_id>, Authorization: Bearer <token>
"""

import argparse
import os
import sys
import time
import uuid
from pathlib import Path

import requests

def headers(agent_id: str, token: str) -> dict:
    return {
        "X-Agent-ID": agent_id,
        "Authorization": f"Bearer {token}",
    }


def main():
    parser = argparse.ArgumentParser(description="Shost agent simulator: get and download next sample")
    parser.add_argument("--base-url", default=os.getenv("SHOST_API_BASE", "http://127.0.0.1:8080/api/v1"), help="API base URL")
    parser.add_argument("--agent-id", default=os.getenv("SHOST_AGENT_ID", "shikra-agent-001"), help="Agent ID to use")
    parser.add_argument("--token", default=os.getenv("SHOST_BEARER_TOKEN", ""), help="Bearer token to use; if empty and --register is set, token from register response will be used")
    parser.add_argument("--register", action="store_true", help="Call /agent/register before polling")
    parser.add_argument("--download-dir", default="/tmp/shikra_downloads", help="Where to save downloaded sample")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    session = requests.Session()

    token = args.token

    if args.register or not token:
        print(f"[info] Registering agent {args.agent_id}...")
        r = session.post(
            f"{base}/agent/register",
            json={"agent_id": args.agent_id, "name": f"Agent {args.agent_id}"},
            timeout=10,
        )
        if r.ok:
            jr = r.json()
            token = jr.get("access_token", token)
            print("[ok] register, token issued")
        else:
            print(f"[warn] register failed: {r.status_code} {r.text}")

    print("[info] Requesting next sample...")
    r = session.get(f"{base}/agent/next-sample", headers=headers(args.agent_id, token), timeout=15)
    if r.status_code == 204:
        print("[info] No samples available (status 204)")
        return 0
    if not r.ok:
        print(f"[error] next-sample failed: {r.status_code} {r.text}")
        return 2

    data = r.json()
    sample_id = data.get("sample_id")
    if not sample_id:
        print("[error] No sample_id in response:", data)
        return 2
    print(f"[ok] Assigned sample {sample_id} ({data.get('filename')}, {data.get('file_size')} bytes)")

    # Download the sample
    outdir = Path(args.download_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    outfile = outdir / f"{sample_id}.bin"
    print(f"[info] Downloading sample to {outfile}...")
    r = session.get(f"{base}/agent/download/{sample_id}", headers=headers(args.agent_id, token), timeout=60, stream=True)
    if not r.ok:
        print(f"[error] download failed: {r.status_code} {r.text}")
        return 2
    with open(outfile, "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
    size = outfile.stat().st_size
    print(f"[ok] Downloaded {size} bytes -> {outfile}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
