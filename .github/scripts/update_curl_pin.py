"""Move the pinned curlimages/curl manifest-list digest when upstream ships a release.

The pin lives in main.py (Docker and Kubernetes sandboxes) and terraform/variables.tf
(the image Terraform imports into ACR). A weekly workflow runs this script and opens
a pull request; applying Terraform is what points the Azure job at the new digest.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request

REPOSITORY = os.environ.get("CURL_REPOSITORY", "curlimages/curl")
PIN_FILES = ("main.py", "terraform/variables.tf")
PIN = re.compile(rf"{re.escape(REPOSITORY)}:\d+\.\d+\.\d+@sha256:[a-f0-9]{{64}}")
RELEASE_TAG = re.compile(r"^\d+\.\d+\.\d+$")
MANIFEST_ACCEPT = (
    "application/vnd.oci.image.index.v1+json, "
    "application/vnd.docker.distribution.manifest.list.v2+json"
)
LIST_TYPES = (
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
)


def _request(url: str, headers: dict[str, str] | None = None, method: str = "GET") -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(url, headers=headers or {}, method=method)
    try:
        response = urllib.request.urlopen(request, timeout=30)
    except urllib.error.HTTPError as exc:
        return exc.code, {key.lower(): value for key, value in exc.headers.items()}, exc.read()
    with response:
        header_map = {key.lower(): value for key, value in response.headers.items()}
        return response.status, header_map, response.read()


def _registry_token() -> str:
    status, _headers, body = _request(
        "https://auth.docker.io/token"
        f"?service=registry.docker.io&scope=repository:{REPOSITORY}:pull"
    )
    if status != 200:
        raise SystemExit(f"Docker Hub token request failed with HTTP {status}.")
    token = json.loads(body.decode()).get("token")
    if not isinstance(token, str) or not token:
        raise SystemExit("Docker Hub token response did not include a token.")
    return token


def _latest_release_tag() -> str:
    versions: list[tuple[int, int, int]] = []
    url = f"https://hub.docker.com/v2/repositories/{REPOSITORY}/tags?page_size=100&ordering=last_updated"
    for _page in range(5):
        status, _headers, body = _request(url)
        if status != 200:
            raise SystemExit(f"Docker Hub tag list failed with HTTP {status}.")
        payload = json.loads(body.decode())
        for item in payload.get("results", []):
            name = item.get("name", "")
            if RELEASE_TAG.fullmatch(name):
                versions.append(tuple(int(part) for part in name.split(".")))
        url = payload.get("next")
        if not url:
            break
    if not versions:
        raise SystemExit(f"No stable {REPOSITORY} release tag was found.")
    latest = max(versions)
    return ".".join(str(part) for part in latest)


def _manifest_list_digest(tag: str, token: str) -> str:
    status, headers, _body = _request(
        f"https://registry-1.docker.io/v2/{REPOSITORY}/manifests/{tag}",
        headers={"Authorization": f"Bearer {token}", "Accept": MANIFEST_ACCEPT},
        method="HEAD",
    )
    if status != 200:
        raise SystemExit(f"Manifest lookup for {REPOSITORY}:{tag} failed with HTTP {status}.")
    content_type = headers.get("content-type", "").split(";", 1)[0].strip()
    if content_type not in LIST_TYPES:
        raise SystemExit(
            f"Refusing to pin {REPOSITORY}:{tag}: registry returned {content_type or 'no content type'}, "
            "not a multi-arch manifest list."
        )
    digest = headers.get("docker-content-digest", "").strip()
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise SystemExit(f"Registry did not return a sha256 digest for {REPOSITORY}:{tag}.")
    return digest


def _write_output(name: str, value: str) -> None:
    print(f"{name}={value}")
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(f"{name}={value}\n")


def _replace_pin(path: str, new_pin: str) -> None:
    file = open(path, encoding="utf-8")
    try:
        original = file.read()
    finally:
        file.close()
    updated, count = PIN.subn(new_pin, original)
    if count == 0:
        raise SystemExit(f"{path} has no {REPOSITORY} digest pin to update.")
    if updated != original:
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(updated)


def main() -> None:
    tag = _latest_release_tag()
    digest = _manifest_list_digest(tag, _registry_token())
    new_pin = f"{REPOSITORY}:{tag}@{digest}"
    changed = False
    for path in PIN_FILES:
        file = open(path, encoding="utf-8")
        try:
            match = PIN.search(file.read())
        finally:
            file.close()
        if match is None:
            raise SystemExit(f"{path} has no {REPOSITORY} digest pin to update.")
        if match.group(0) != new_pin:
            changed = True
    if changed:
        for path in PIN_FILES:
            _replace_pin(path, new_pin)
        with open("curl-pin-body.md", "w", encoding="utf-8", newline="\n") as handle:
            handle.write(
                "## Summary\n"
                f"- Pin `{REPOSITORY}` to `{tag}` (`{digest}`), the current multi-arch manifest list.\n"
                "- `main.py` is the Docker and Kubernetes sandbox image. "
                "`terraform/variables.tf` is the upstream image Terraform imports into ACR.\n"
                "- Apply Terraform to import this digest and point the sandbox job at the ACR copy. "
                "The job does not pull Docker Hub.\n\n"
                "## Test plan\n"
                "- [ ] `pytest` still passes\n"
                f"- [ ] `terraform plan` shows an ACR import and a job image of `<registry>/curl@{digest}`\n"
            )
    _write_output("updated", "true" if changed else "false")
    _write_output("tag", tag)
    _write_output("digest", digest)


if __name__ == "__main__":
    try:
        main()
    except urllib.error.URLError as exc:
        raise SystemExit(f"Could not reach Docker Hub: {exc}") from exc
