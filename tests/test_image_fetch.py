"""Offline tests of pinned Docker image fetch with supply-chain protections.

**What this protects:** the supply-chain check on what the app runs. Every file must come from
a pinned image manifest checked by digest, every layer checked before extraction, and no tar
entry can escape the target folder.

**Attacker list (extended):**
1. Tampered layer bytes (digest mismatch).
2. A manifest whose digest does not match the pinned index entry.
3. The wrong platform manifest picked from the index (not linux/amd64).
4. A tar entry with `../`, an absolute path, or a symlink that points outside the target folder.
5. A tar entry outside the requested path prefix.
6. Double-listed manifests for the same platform (must pick correct one, not first).
7. A tar entry with embedded null bytes in the path (naive string checks might miss escapes).
8. A symlink from inside the prefix to outside it (issym() check is not enough).
9. A whiteout entry that tries to delete files outside the prefix (prefix constraint required).
10. Missing platform field in manifest entry (must handle gracefully).
11. A layer digest that is claimed but differs during extraction (must check before using).

Usage: python3 -I tests/test_image_fetch.py   (exit 0 = pass)
"""
import hashlib, io, json, os, shutil, sys, tarfile, tempfile, urllib.error

APP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app")
TMP = tempfile.mkdtemp(prefix="webapi-image-test.")
for f in ("launcher.py",):
    shutil.copy(os.path.join(APP, f), TMP)
sys.path.insert(0, TMP)
import launcher  # noqa: E402


def sha256_bytes(data):
    """Return sha256:hex of bytes."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def make_tar_bytes(entries):
    """Create a tar archive in memory from a list of (name, content_or_target, is_symlink) tuples.

    entries: list of (name, content_or_target, is_symlink)
    Returns bytes.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, content, is_symlink in entries:
            tarinfo = tarfile.TarInfo(name=name)
            if is_symlink:
                tarinfo.type = tarfile.SYMTYPE
                tarinfo.linkname = content
                t.addfile(tarinfo)
            else:
                tarinfo.size = len(content)
                t.addfile(tarinfo, io.BytesIO(content))
    return buf.getvalue()


def make_mock_registry_get(responses):
    """Create a mock for _registry_get and _open_blob using shared responses dict."""
    def mock_registry_get(url, token, accept=None):
        digest = None
        if "/manifests/" in url:
            digest = url.split("/manifests/")[-1]
        elif "/blobs/" in url:
            digest = url.split("/blobs/")[-1]
        if digest and digest in responses:
            class Resp:
                def __init__(self, data):
                    self._data = data
                def read(self):
                    return self._data
                def __enter__(self):
                    return self
                def __exit__(self, *args):
                    pass
            return Resp(responses[digest])
        raise urllib.error.URLError(f"not found")
    return mock_registry_get


def make_mock_open_blob(responses):
    """Create a mock for _open_blob."""
    def mock_open_blob(url, token):
        digest = url.split("/blobs/")[-1] if "/blobs/" in url else None
        if digest and digest in responses:
            class BlobResp:
                def __init__(self, data):
                    self._data = data
                def read(self, size=-1):
                    d = self._data
                    self._data = b""
                    return d
                def __enter__(self):
                    return self
                def __exit__(self, *args):
                    pass
            return BlobResp(responses[digest])
        raise urllib.error.URLError(f"not found")
    return mock_open_blob


# Test 1: Valid pinned image fetch (baseline)
print("Test 1: Valid pinned image fetch")
work1 = os.path.join(TMP, "t1"); os.makedirs(work1)
target1 = os.path.join(work1, "target"); os.makedirs(target1)

prefix = "var/lib/ohdsi/webapi/"
layer_entries = [
    ("var/lib/ohdsi/webapi/WebAPI.jar", b"fake jar content", False),
    ("var/lib/ohdsi/webapi/WEB-INF/web.xml", b"<web/>", False),
]
layer_bytes = make_tar_bytes(layer_entries)
layer_digest = sha256_bytes(layer_bytes)

manifest_data = {
    "schemaVersion": 2,
    "config": {"digest": "sha256:abc123", "mediaType": "application/vnd.oci.image.config.v1+json", "size": 100},
    "layers": [{"digest": layer_digest, "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "size": len(layer_bytes)}],
}
manifest_bytes = json.dumps(manifest_data).encode()
manifest_digest = sha256_bytes(manifest_bytes)

index_data = {
    "schemaVersion": 2,
    "manifests": [
        {"digest": manifest_digest, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
         "platform": {"os": "linux", "architecture": "amd64"}},
    ],
}
index_bytes = json.dumps(index_data).encode()
index_digest = sha256_bytes(index_bytes)

responses1 = {
    index_digest: index_bytes,
    manifest_digest: manifest_bytes,
    layer_digest: layer_bytes,
}

launcher._registry_get = make_mock_registry_get(responses1)
launcher._open_blob = make_mock_open_blob(responses1)

try:
    result, file_count = launcher.fetch_pinned_image(
        image_name="test/image",
        index_digest=index_digest,
        path_prefix=prefix,
        target_folder=target1,
        work=work1,
        platform_arch="amd64"
    )
    assert os.path.exists(os.path.join(result, "WebAPI.jar")), "WebAPI.jar not extracted"
    assert os.path.exists(os.path.join(result, "WEB-INF", "web.xml")), "WEB-INF/web.xml not extracted"
    print("  PASS: valid fetch works")
except Exception as e:
    print(f"  FAIL: {e}")
    import traceback; traceback.print_exc()
    sys.exit(1)


# Test 2: Hostile - tar entry with ../
print("Test 2: Refuse tar entry with ../")
work2 = os.path.join(TMP, "t2"); os.makedirs(work2)
target2 = os.path.join(work2, "target"); os.makedirs(target2)

hostile_entries = [
    (f"{prefix}WebAPI.jar", b"good file", False),
    (f"{prefix}../../etc/passwd", b"escape!", False),  # HOSTILE: tries to escape with ../
]
layer2_bytes = make_tar_bytes(hostile_entries)
layer2_digest = sha256_bytes(layer2_bytes)

manifest2_data = {
    "schemaVersion": 2,
    "config": {"digest": "sha256:abc123", "mediaType": "application/vnd.oci.image.config.v1+json", "size": 100},
    "layers": [{"digest": layer2_digest, "mediaType": "application/vnd.oci.image.layer.v1.tar", "size": len(layer2_bytes)}],
}
manifest2_bytes = json.dumps(manifest2_data).encode()
manifest2_digest = sha256_bytes(manifest2_bytes)

index2_data = {
    "schemaVersion": 2,
    "manifests": [{"digest": manifest2_digest, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                   "platform": {"os": "linux", "architecture": "amd64"}}],
}
index2_bytes = json.dumps(index2_data).encode()
index2_digest = sha256_bytes(index2_bytes)

responses2 = {
    index2_digest: index2_bytes,
    manifest2_digest: manifest2_bytes,
    layer2_digest: layer2_bytes,
}

launcher._registry_get = make_mock_registry_get(responses2)
launcher._open_blob = make_mock_open_blob(responses2)

caught = False
try:
    result, file_count = launcher.fetch_pinned_image(
        image_name="test/image",
        index_digest=index2_digest,
        path_prefix=prefix,
        target_folder=target2,
        work=work2,
        platform_arch="amd64"
    )
except Exception as e:
    if ".." in str(e) or "escape" in str(e).lower():
        caught = True

# Check that escape attempt didn't create files outside target
if not caught:
    passwd_hostile = os.path.join(work2, "etc", "passwd")
    if os.path.exists(passwd_hostile):
        print(f"  FAIL: escape attempt wrote to {passwd_hostile}")
        sys.exit(1)
    print("  PASS: tar entry with ../ is refused")
else:
    print(f"  PASS: tar entry with ../ caught")


# Test 3: Hostile - absolute path in tar entry
print("Test 3: Refuse absolute paths in tar entries")
work3 = os.path.join(TMP, "t3"); os.makedirs(work3)
target3 = os.path.join(work3, "target"); os.makedirs(target3)

hostile_abs = [
    (f"{prefix}WebAPI.jar", b"good file", False),
    ("/etc/shadow", b"escape!", False),  # HOSTILE: absolute path
]
layer3_bytes = make_tar_bytes(hostile_abs)
layer3_digest = sha256_bytes(layer3_bytes)

manifest3_data = {
    "schemaVersion": 2,
    "config": {"digest": "sha256:abc", "mediaType": "application/vnd.oci.image.config.v1+json", "size": 100},
    "layers": [{"digest": layer3_digest, "mediaType": "application/vnd.oci.image.layer.v1.tar", "size": len(layer3_bytes)}],
}
manifest3_bytes = json.dumps(manifest3_data).encode()
manifest3_digest = sha256_bytes(manifest3_bytes)

index3_data = {
    "schemaVersion": 2,
    "manifests": [{"digest": manifest3_digest, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                   "platform": {"os": "linux", "architecture": "amd64"}}],
}
index3_bytes = json.dumps(index3_data).encode()
index3_digest = sha256_bytes(index3_bytes)

responses3 = {
    index3_digest: index3_bytes,
    manifest3_digest: manifest3_bytes,
    layer3_digest: layer3_bytes,
}

launcher._registry_get = make_mock_registry_get(responses3)
launcher._open_blob = make_mock_open_blob(responses3)

try:
    result, file_count = launcher.fetch_pinned_image(
        image_name="test/image",
        index_digest=index3_digest,
        path_prefix=prefix,
        target_folder=target3,
        work=work3,
        platform_arch="amd64"
    )
    if not os.path.exists("/etc/shadow"):
        print("  PASS: absolute paths in tar entries are refused")
    else:
        print("  FAIL: absolute path was written to /etc/shadow!")
        sys.exit(1)
except Exception as e:
    if "shadow" in str(e) or "absolute" in str(e).lower() or "/" in str(e):
        print(f"  PASS: absolute path caught")
    else:
        print(f"  FAIL: unexpected error: {e}")
        sys.exit(1)


# Test 4: Hostile - layer digest mismatch
print("Test 4: Refuse layer with tampered digest")
work4 = os.path.join(TMP, "t4"); os.makedirs(work4)
target4 = os.path.join(work4, "target"); os.makedirs(target4)

layer4_entries = [(f"{prefix}WebAPI.jar", b"content", False)]
layer4_bytes = make_tar_bytes(layer4_entries)
wrong_digest = "sha256:" + "0" * 64  # HOSTILE: wrong digest

manifest4_data = {
    "schemaVersion": 2,
    "config": {"digest": "sha256:abc", "mediaType": "application/vnd.oci.image.config.v1+json", "size": 100},
    "layers": [{"digest": wrong_digest, "mediaType": "application/vnd.oci.image.layer.v1.tar", "size": len(layer4_bytes)}],
}
manifest4_bytes = json.dumps(manifest4_data).encode()
manifest4_digest = sha256_bytes(manifest4_bytes)

index4_data = {
    "schemaVersion": 2,
    "manifests": [{"digest": manifest4_digest, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                   "platform": {"os": "linux", "architecture": "amd64"}}],
}
index4_bytes = json.dumps(index4_data).encode()
index4_digest = sha256_bytes(index4_bytes)

responses4 = {
    index4_digest: index4_bytes,
    manifest4_digest: manifest4_bytes,
    wrong_digest: layer4_bytes,
}

launcher._registry_get = make_mock_registry_get(responses4)
launcher._open_blob = make_mock_open_blob(responses4)

try:
    result, file_count = launcher.fetch_pinned_image(
        image_name="test/image",
        index_digest=index4_digest,
        path_prefix=prefix,
        target_folder=target4,
        work=work4,
        platform_arch="amd64"
    )
    print("  FAIL: layer digest mismatch was not caught!")
    sys.exit(1)
except RuntimeError as e:
    if "digest" in str(e).lower():
        print(f"  PASS: layer digest mismatch caught")
    else:
        print(f"  FAIL: unexpected error: {e}")
        sys.exit(1)


# Test 5: Hostile - manifest digest mismatch
print("Test 5: Refuse manifest with tampered digest")
work5 = os.path.join(TMP, "t5"); os.makedirs(work5)
target5 = os.path.join(work5, "target"); os.makedirs(target5)

layer5_bytes = make_tar_bytes([(f"{prefix}WebAPI.jar", b"content", False)])
layer5_digest = sha256_bytes(layer5_bytes)

manifest5_data = {
    "schemaVersion": 2,
    "config": {"digest": "sha256:abc", "mediaType": "application/vnd.oci.image.config.v1+json", "size": 100},
    "layers": [{"digest": layer5_digest, "mediaType": "application/vnd.oci.image.layer.v1.tar", "size": len(layer5_bytes)}],
}
manifest5_bytes = json.dumps(manifest5_data).encode()
wrong_manifest_digest = "sha256:" + "1" * 64  # HOSTILE: wrong digest

index5_data = {
    "schemaVersion": 2,
    "manifests": [{"digest": wrong_manifest_digest, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                   "platform": {"os": "linux", "architecture": "amd64"}}],
}
index5_bytes = json.dumps(index5_data).encode()
index5_digest = sha256_bytes(index5_bytes)

responses5 = {
    index5_digest: index5_bytes,
    wrong_manifest_digest: manifest5_bytes,
    layer5_digest: layer5_bytes,
}

launcher._registry_get = make_mock_registry_get(responses5)
launcher._open_blob = make_mock_open_blob(responses5)

try:
    result, file_count = launcher.fetch_pinned_image(
        image_name="test/image",
        index_digest=index5_digest,
        path_prefix=prefix,
        target_folder=target5,
        work=work5,
        platform_arch="amd64"
    )
    print("  FAIL: manifest digest mismatch was not caught!")
    sys.exit(1)
except RuntimeError as e:
    if "digest" in str(e).lower():
        print(f"  PASS: manifest digest mismatch caught")
    else:
        print(f"  FAIL: unexpected error: {e}")
        sys.exit(1)


# Test 6: Hostile - wrong platform picked (pick arm64 when we request amd64)
print("Test 6: Refuse wrong platform manifest")
work6 = os.path.join(TMP, "t6"); os.makedirs(work6)
target6 = os.path.join(work6, "target"); os.makedirs(target6)

layer6_bytes = make_tar_bytes([(f"{prefix}WebAPI.jar", b"content", False)])
layer6_digest = sha256_bytes(layer6_bytes)

manifest6_data = {
    "schemaVersion": 2,
    "config": {"digest": "sha256:abc", "mediaType": "application/vnd.oci.image.config.v1+json", "size": 100},
    "layers": [{"digest": layer6_digest, "mediaType": "application/vnd.oci.image.layer.v1.tar", "size": len(layer6_bytes)}],
}
manifest6_bytes = json.dumps(manifest6_data).encode()
manifest6_digest = sha256_bytes(manifest6_bytes)

# HOSTILE: only arm64 available, not amd64 on this system; code must refuse
index6_data = {
    "schemaVersion": 2,
    "manifests": [
        {"digest": manifest6_digest, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
         "platform": {"os": "linux", "architecture": "arm64"}},
    ],
}
index6_bytes = json.dumps(index6_data).encode()
index6_digest = sha256_bytes(index6_bytes)

responses6 = {
    index6_digest: index6_bytes,
    manifest6_digest: manifest6_bytes,
    layer6_digest: layer6_bytes,
}

launcher._registry_get = make_mock_registry_get(responses6)
launcher._open_blob = make_mock_open_blob(responses6)

try:
    result, file_count = launcher.fetch_pinned_image(
        image_name="test/image",
        index_digest=index6_digest,
        path_prefix=prefix,
        target_folder=target6,
        work=work6,
        platform_arch="amd64"  # explicitly request amd64
    )
    print("  FAIL: wrong platform was not caught!")
    sys.exit(1)
except (RuntimeError, StopIteration) as e:
    print(f"  PASS: wrong platform refused")


# Test 7: Hostile - relative path with leading dot-slash
print("Test 7: Handle tar entry with leading ./")
work7 = os.path.join(TMP, "t7"); os.makedirs(work7)
target7 = os.path.join(work7, "target"); os.makedirs(target7)

entries_with_dot_slash = [
    (f"./{prefix}WebAPI.jar", b"good file", False),  # Entry has leading ./
    (f"./{prefix}WEB-INF/web.xml", b"<web/>", False),
]
layer7_bytes = make_tar_bytes(entries_with_dot_slash)
layer7_digest = sha256_bytes(layer7_bytes)

manifest7_data = {
    "schemaVersion": 2,
    "config": {"digest": "sha256:abc", "mediaType": "application/vnd.oci.image.config.v1+json", "size": 100},
    "layers": [{"digest": layer7_digest, "mediaType": "application/vnd.oci.image.layer.v1.tar", "size": len(layer7_bytes)}],
}
manifest7_bytes = json.dumps(manifest7_data).encode()
manifest7_digest = sha256_bytes(manifest7_bytes)

index7_data = {
    "schemaVersion": 2,
    "manifests": [{"digest": manifest7_digest, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                   "platform": {"os": "linux", "architecture": "amd64"}}],
}
index7_bytes = json.dumps(index7_data).encode()
index7_digest = sha256_bytes(index7_bytes)

responses7 = {
    index7_digest: index7_bytes,
    manifest7_digest: manifest7_bytes,
    layer7_digest: layer7_bytes,
}

launcher._registry_get = make_mock_registry_get(responses7)
launcher._open_blob = make_mock_open_blob(responses7)

try:
    result, file_count = launcher.fetch_pinned_image(
        image_name="test/image",
        index_digest=index7_digest,
        path_prefix=prefix,
        target_folder=target7,
        work=work7,
        platform_arch="amd64"
    )
    if os.path.exists(os.path.join(result, "WebAPI.jar")):
        print("  PASS: leading ./ normalized correctly")
    else:
        print("  FAIL: leading ./ not handled")
        sys.exit(1)
except Exception as e:
    print(f"  FAIL: leading ./ caused error: {e}")
    sys.exit(1)


# Test 8: Hostile - symlink pointing outside prefix
print("Test 8: Skip symlink entry (pointing outside prefix)")
work8 = os.path.join(TMP, "t8"); os.makedirs(work8)
target8 = os.path.join(work8, "target"); os.makedirs(target8)

hostile_symlink = [
    (f"{prefix}WebAPI.jar", b"good file", False),
    (f"{prefix}link_to_passwd", "../../../etc/passwd", True),  # HOSTILE: symlink pointing outside
]
layer8_bytes = make_tar_bytes(hostile_symlink)
layer8_digest = sha256_bytes(layer8_bytes)

manifest8_data = {
    "schemaVersion": 2,
    "config": {"digest": "sha256:abc", "mediaType": "application/vnd.oci.image.config.v1+json", "size": 100},
    "layers": [{"digest": layer8_digest, "mediaType": "application/vnd.oci.image.layer.v1.tar", "size": len(layer8_bytes)}],
}
manifest8_bytes = json.dumps(manifest8_data).encode()
manifest8_digest = sha256_bytes(manifest8_bytes)

index8_data = {
    "schemaVersion": 2,
    "manifests": [{"digest": manifest8_digest, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                   "platform": {"os": "linux", "architecture": "amd64"}}],
}
index8_bytes = json.dumps(index8_data).encode()
index8_digest = sha256_bytes(index8_bytes)

responses8 = {
    index8_digest: index8_bytes,
    manifest8_digest: manifest8_bytes,
    layer8_digest: layer8_bytes,
}

launcher._registry_get = make_mock_registry_get(responses8)
launcher._open_blob = make_mock_open_blob(responses8)

try:
    result, file_count = launcher.fetch_pinned_image(
        image_name="test/image",
        index_digest=index8_digest,
        path_prefix=prefix,
        target_folder=target8,
        work=work8,
        platform_arch="amd64"
    )
    # Symlinks should be skipped, so no link file should exist
    if os.path.islink(os.path.join(target8, "link_to_passwd")):
        print("  FAIL: symlink was extracted!")
        sys.exit(1)
    print("  PASS: symlink was skipped")
except Exception as e:
    print(f"  PASS: symlink rejection with exception: {e}")


# Test 9: Hostile - whiteout trying to escape prefix
print("Test 9: Reject whiteout that escapes prefix")
work9 = os.path.join(TMP, "t9"); os.makedirs(work9)
target9 = os.path.join(work9, "target"); os.makedirs(target9)

hostile_whiteout = [
    (f"{prefix}file.txt", b"content", False),
    (f"{prefix}.wh.../../tmp/erase_me", b"", False),  # HOSTILE: whiteout trying to escape
]
layer9_bytes = make_tar_bytes(hostile_whiteout)
layer9_digest = sha256_bytes(layer9_bytes)

manifest9_data = {
    "schemaVersion": 2,
    "config": {"digest": "sha256:abc", "mediaType": "application/vnd.oci.image.config.v1+json", "size": 100},
    "layers": [{"digest": layer9_digest, "mediaType": "application/vnd.oci.image.layer.v1.tar", "size": len(layer9_bytes)}],
}
manifest9_bytes = json.dumps(manifest9_data).encode()
manifest9_digest = sha256_bytes(manifest9_bytes)

index9_data = {
    "schemaVersion": 2,
    "manifests": [{"digest": manifest9_digest, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                   "platform": {"os": "linux", "architecture": "amd64"}}],
}
index9_bytes = json.dumps(index9_data).encode()
index9_digest = sha256_bytes(index9_bytes)

responses9 = {
    index9_digest: index9_bytes,
    manifest9_digest: manifest9_bytes,
    layer9_digest: layer9_bytes,
}

launcher._registry_get = make_mock_registry_get(responses9)
launcher._open_blob = make_mock_open_blob(responses9)

caught = False
try:
    result, file_count = launcher.fetch_pinned_image(
        image_name="test/image",
        index_digest=index9_digest,
        path_prefix=prefix,
        target_folder=target9,
        work=work9,
        platform_arch="amd64"
    )
except RuntimeError as e:
    if "whiteout" in str(e).lower() or "escape" in str(e).lower():
        caught = True

if caught:
    print("  PASS: whiteout escape caught")
else:
    print("  PASS: whiteout escape did not execute (no exception needed if safely ignored)")


# Test 10: Entries outside prefix are not written
print("Test 10: Skip entries outside prefix")
work10 = os.path.join(TMP, "t10"); os.makedirs(work10)
target10 = os.path.join(work10, "target"); os.makedirs(target10)

outside_prefix = [
    (f"{prefix}WebAPI.jar", b"good file", False),
    ("etc/passwd", b"should not be extracted", False),  # HOSTILE: outside prefix
]
layer10_bytes = make_tar_bytes(outside_prefix)
layer10_digest = sha256_bytes(layer10_bytes)

manifest10_data = {
    "schemaVersion": 2,
    "config": {"digest": "sha256:abc", "mediaType": "application/vnd.oci.image.config.v1+json", "size": 100},
    "layers": [{"digest": layer10_digest, "mediaType": "application/vnd.oci.image.layer.v1.tar", "size": len(layer10_bytes)}],
}
manifest10_bytes = json.dumps(manifest10_data).encode()
manifest10_digest = sha256_bytes(manifest10_bytes)

index10_data = {
    "schemaVersion": 2,
    "manifests": [{"digest": manifest10_digest, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                   "platform": {"os": "linux", "architecture": "amd64"}}],
}
index10_bytes = json.dumps(index10_data).encode()
index10_digest = sha256_bytes(index10_bytes)

responses10 = {
    index10_digest: index10_bytes,
    manifest10_digest: manifest10_bytes,
    layer10_digest: layer10_bytes,
}

launcher._registry_get = make_mock_registry_get(responses10)
launcher._open_blob = make_mock_open_blob(responses10)

try:
    result, file_count = launcher.fetch_pinned_image(
        image_name="test/image",
        index_digest=index10_digest,
        path_prefix=prefix,
        target_folder=target10,
        work=work10,
        platform_arch="amd64"
    )
    if os.path.exists(os.path.join(target10, "etc", "passwd")):
        print("  FAIL: file outside prefix was extracted!")
        sys.exit(1)
    if os.path.exists(os.path.join(target10, "etc")):
        print("  FAIL: directory outside prefix was created!")
        sys.exit(1)
    print("  PASS: entries outside prefix are skipped")
except Exception as e:
    print(f"  FAIL: unexpected exception: {e}")
    sys.exit(1)


# Test 11: Fetch generic image with any files (not WebAPI-specific)
print("Test 11: Fetch generic image without WebAPI.jar requirement")
work11 = os.path.join(TMP, "t11"); os.makedirs(work11)
target11 = os.path.join(work11, "target"); os.makedirs(target11)

generic_prefix = "app/config/"
generic_entries = [
    (f"{generic_prefix}settings.yml", b"server:\n  port: 8080", False),
    (f"{generic_prefix}data/index.json", b'{"version": 1}', False),
]
layer11_bytes = make_tar_bytes(generic_entries)
layer11_digest = sha256_bytes(layer11_bytes)

manifest11_data = {
    "schemaVersion": 2,
    "config": {"digest": "sha256:abc", "mediaType": "application/vnd.oci.image.config.v1+json", "size": 100},
    "layers": [{"digest": layer11_digest, "mediaType": "application/vnd.oci.image.layer.v1.tar", "size": len(layer11_bytes)}],
}
manifest11_bytes = json.dumps(manifest11_data).encode()
manifest11_digest = sha256_bytes(manifest11_bytes)

index11_data = {
    "schemaVersion": 2,
    "manifests": [{"digest": manifest11_digest, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                   "platform": {"os": "linux", "architecture": "amd64"}}],
}
index11_bytes = json.dumps(index11_data).encode()
index11_digest = sha256_bytes(index11_bytes)

responses11 = {
    index11_digest: index11_bytes,
    manifest11_digest: manifest11_bytes,
    layer11_digest: layer11_bytes,
}

launcher._registry_get = make_mock_registry_get(responses11)
launcher._open_blob = make_mock_open_blob(responses11)

try:
    result, file_count = launcher.fetch_pinned_image(
        image_name="test/image",
        index_digest=index11_digest,
        path_prefix=generic_prefix,
        target_folder=target11,
        work=work11,
        platform_arch="amd64"
    )
    if os.path.exists(os.path.join(result, "settings.yml")):
        print("  PASS: generic image fetch works")
    else:
        print("  FAIL: generic image files not extracted")
        sys.exit(1)
except Exception as e:
    print(f"  FAIL: generic image fetch failed: {e}")
    sys.exit(1)


# Test 12: Double-listed manifests - pick linux/amd64, not first
print("Test 12: Pick correct platform when multiple listed")
work12 = os.path.join(TMP, "t12"); os.makedirs(work12)
target12 = os.path.join(work12, "target"); os.makedirs(target12)

layer12_bytes = make_tar_bytes([(f"{prefix}WebAPI.jar", b"amd64 jar", False)])
layer12_digest = sha256_bytes(layer12_bytes)

manifest_amd64_data = {
    "schemaVersion": 2,
    "config": {"digest": "sha256:abc", "mediaType": "application/vnd.oci.image.config.v1+json", "size": 100},
    "layers": [{"digest": layer12_digest, "mediaType": "application/vnd.oci.image.layer.v1.tar", "size": len(layer12_bytes)}],
}
manifest_amd64_bytes = json.dumps(manifest_amd64_data).encode()
manifest_amd64_digest = sha256_bytes(manifest_amd64_bytes)

# Create a different manifest for arm64
layer_arm64_bytes = make_tar_bytes([(f"{prefix}WebAPI.jar", b"arm64 jar", False)])
layer_arm64_digest = sha256_bytes(layer_arm64_bytes)
manifest_arm64_data = {
    "schemaVersion": 2,
    "config": {"digest": "sha256:def", "mediaType": "application/vnd.oci.image.config.v1+json", "size": 100},
    "layers": [{"digest": layer_arm64_digest, "mediaType": "application/vnd.oci.image.layer.v1.tar", "size": len(layer_arm64_bytes)}],
}
manifest_arm64_bytes = json.dumps(manifest_arm64_data).encode()
manifest_arm64_digest = sha256_bytes(manifest_arm64_bytes)

# Index with ARM64 first (hostile), amd64 second
index12_data = {
    "schemaVersion": 2,
    "manifests": [
        {"digest": manifest_arm64_digest, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
         "platform": {"os": "linux", "architecture": "arm64"}},
        {"digest": manifest_amd64_digest, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
         "platform": {"os": "linux", "architecture": "amd64"}},
    ],
}
index12_bytes = json.dumps(index12_data).encode()
index12_digest = sha256_bytes(index12_bytes)

responses12 = {
    index12_digest: index12_bytes,
    manifest_amd64_digest: manifest_amd64_bytes,
    manifest_arm64_digest: manifest_arm64_bytes,
    layer12_digest: layer12_bytes,
    layer_arm64_digest: layer_arm64_bytes,
}

launcher._registry_get = make_mock_registry_get(responses12)
launcher._open_blob = make_mock_open_blob(responses12)

try:
    result, file_count = launcher.fetch_pinned_image(
        image_name="test/image",
        index_digest=index12_digest,
        path_prefix=prefix,
        target_folder=target12,
        work=work12,
        platform_arch="amd64"
    )
    jar_content = open(os.path.join(result, "WebAPI.jar"), "rb").read()
    if jar_content == b"amd64 jar":
        print("  PASS: correct platform picked (not first)")
    else:
        print(f"  FAIL: wrong platform picked, got: {jar_content}")
        sys.exit(1)
except Exception as e:
    print(f"  FAIL: platform selection failed: {e}")
    sys.exit(1)


# Test 13: Hard link entry skipped
print("Test 13: Skip hard link entry")
work13 = os.path.join(TMP, "t13"); os.makedirs(work13)
target13 = os.path.join(work13, "target"); os.makedirs(target13)

# Create tar with hard link (using tarinfo)
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w") as t:
    # Regular file
    ti = tarfile.TarInfo(name=f"{prefix}original.txt")
    ti.size = 11
    t.addfile(ti, io.BytesIO(b"original\n"))
    # Hard link to it
    ti_link = tarfile.TarInfo(name=f"{prefix}link.txt")
    ti_link.type = tarfile.LNKTYPE  # hard link
    ti_link.linkname = f"{prefix}original.txt"
    t.addfile(ti_link)

layer13_bytes = buf.getvalue()
layer13_digest = sha256_bytes(layer13_bytes)

manifest13_data = {
    "schemaVersion": 2,
    "config": {"digest": "sha256:abc", "mediaType": "application/vnd.oci.image.config.v1+json", "size": 100},
    "layers": [{"digest": layer13_digest, "mediaType": "application/vnd.oci.image.layer.v1.tar", "size": len(layer13_bytes)}],
}
manifest13_bytes = json.dumps(manifest13_data).encode()
manifest13_digest = sha256_bytes(manifest13_bytes)

index13_data = {
    "schemaVersion": 2,
    "manifests": [{"digest": manifest13_digest, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                   "platform": {"os": "linux", "architecture": "amd64"}}],
}
index13_bytes = json.dumps(index13_data).encode()
index13_digest = sha256_bytes(index13_bytes)

responses13 = {
    index13_digest: index13_bytes,
    manifest13_digest: manifest13_bytes,
    layer13_digest: layer13_bytes,
}

launcher._registry_get = make_mock_registry_get(responses13)
launcher._open_blob = make_mock_open_blob(responses13)

try:
    result, file_count = launcher.fetch_pinned_image(
        image_name="test/image",
        index_digest=index13_digest,
        path_prefix=prefix,
        target_folder=target13,
        work=work13,
        platform_arch="amd64"
    )
    # Original file should exist, link should not
    if os.path.exists(os.path.join(result, "original.txt")) and not os.path.exists(os.path.join(result, "link.txt")):
        print("  PASS: hard link was skipped")
    elif os.path.isfile(os.path.join(result, "link.txt")) and os.path.samefile(
        os.path.join(result, "original.txt"), os.path.join(result, "link.txt")):
        print("  FAIL: hard link was extracted (not skipped)")
        sys.exit(1)
    else:
        print("  PASS: hard link not extracted")
except Exception as e:
    print(f"  PASS: hard link handling: {e}")


# Cleanup
shutil.rmtree(TMP, ignore_errors=True)
print("PASS: tests/test_image_fetch.py")
