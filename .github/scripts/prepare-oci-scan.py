#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Expose each helper platform directly for Trivy's OCI digest selection."""

import hashlib
import json
import os
from pathlib import Path
import re
import sys

INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
IMAGE_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}


def prepare(layout, output):
    selected = {}

    def blob(descriptor):
        digest = descriptor["digest"]
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("expected a sha256 OCI digest")
        data = (layout / "blobs" / "sha256" / digest[7:]).read_bytes()
        if hashlib.sha256(data).hexdigest() != digest[7:]:
            raise ValueError(f"OCI blob checksum mismatch: {digest}")
        return json.loads(data)

    def visit(descriptor):
        media_type = descriptor["mediaType"]
        if media_type in INDEX_TYPES:
            for child in blob(descriptor)["manifests"]:
                visit(child)
        elif media_type in IMAGE_TYPES:
            if descriptor.get("annotations", {}).get("vnd.docker.reference.type") == "attestation-manifest":
                return
            platform = descriptor.get("platform", {})
            arch = platform.get("architecture")
            if platform.get("os") != "linux" or arch not in ("amd64", "arm64"):
                return
            config = blob(blob(descriptor)["config"])
            if config.get("os") != "linux" or config.get("architecture") != arch:
                raise ValueError(f"OCI descriptor/config platform mismatch: {arch}")
            if arch in selected:
                raise ValueError(f"multiple OCI images for linux/{arch}")
            selected[arch] = descriptor

    index_path = layout / "index.json"
    index = json.loads(index_path.read_text())
    for descriptor in index["manifests"]:
        visit(descriptor)
    if set(selected) != {"amd64", "arm64"}:
        raise ValueError("expected exactly one image each for linux/amd64 and linux/arm64")

    # Trivy v0.70 selects the first child of nested indexes regardless of
    # --platform. Flatten only the scan index; keep every content blob intact.
    index["manifests"] = [selected[arch] for arch in ("amd64", "arm64")]
    temporary = layout / "index.scan.tmp"
    temporary.write_text(json.dumps(index) + "\n")
    temporary.replace(index_path)
    with output.open("a") as stream:
        for arch in ("amd64", "arm64"):
            stream.write(f"{arch}={selected[arch]['digest']}\n")


if __name__ == "__main__":
    prepare(Path(sys.argv[1]), Path(os.environ["GITHUB_OUTPUT"]))
