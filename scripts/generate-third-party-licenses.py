#!/usr/bin/env python3
"""Write or verify THIRD_PARTY.md from `cargo metadata`, vendored C headers,
in-tree font license files, and `android/app/build.gradle.kts`.

Does not invent licenses. A crate or Gradle artifact with no verified license
metadata is recorded as undeclared (and fails `--check` if unexpected).
Re-run from the repository root after a lockfile, asset, or Gradle change:

    python3 scripts/generate-third-party-licenses.py
    python3 scripts/generate-third-party-licenses.py --check
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "THIRD_PARTY.md"
MINIH264_HEADER = ROOT / "crates/agentlink-desktop/vendor/minih264e.h"
ANDROID_APP_GRADLE = ROOT / "android/app/build.gradle.kts"

# Verified against primary upstream repository license files (not guessed):
# - AndroidX / Jetpack Compose: https://cs.android.com/androidx (Apache-2.0)
# - JNA 5.15.0: https://github.com/java-native-access/jna/blob/5.15.0/LICENSE
#   (SPDX-License-Identifier: Apache-2.0 OR LGPL-2.1-or-later; bundled native
#   helpers such as libffi retain their own permissive notices in JNA's NOTICE)
# - RikkaApps Shizuku-API 13.1.5: https://github.com/RikkaApps/Shizuku-API/blob/master/LICENSE (MIT)
# - kotlinx.coroutines 1.9.0: https://github.com/Kotlin/kotlinx.coroutines/blob/master/LICENSE.txt (Apache-2.0)
# - Robolectric 4.14.1: https://github.com/robolectric/robolectric/blob/master/LICENSE (MIT AND Apache-2.0)
# - JUnit 4.13.2: https://github.com/junit-team/junit4/blob/main/LICENSE-junit.txt (EPL-1.0)
ANDROID_DECLARED_LICENSES: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"^androidx\."), "Apache-2.0", "https://cs.android.com/androidx"),
    (
        re.compile(r"^net\.java\.dev\.jna:jna:"),
        "Apache-2.0 OR LGPL-2.1-or-later",
        "https://github.com/java-native-access/jna",
    ),
    (
        re.compile(r"^dev\.rikka\.shizuku:"),
        "MIT",
        "https://github.com/RikkaApps/Shizuku-API",
    ),
    (
        re.compile(r"^org\.jetbrains\.kotlinx:kotlinx-coroutines"),
        "Apache-2.0",
        "https://github.com/Kotlin/kotlinx.coroutines",
    ),
    (
        re.compile(r"^org\.robolectric:robolectric:"),
        "MIT AND Apache-2.0",
        "https://github.com/robolectric/robolectric",
    ),
    (
        re.compile(r"^junit:junit:"),
        "EPL-1.0",
        "https://github.com/junit-team/junit4",
    ),
]


def cargo_metadata() -> dict:
    cmd = [
        "cargo",
        "metadata",
        "--format-version",
        "1",
        "--offline",
        "--locked",
        "--manifest-path",
        str(ROOT / "Cargo.toml"),
    ]
    raw = subprocess.check_output(cmd, cwd=ROOT)
    return json.loads(raw)


def parse_android_gradle_deps() -> tuple[list[dict], list[str]]:
    if not ANDROID_APP_GRADLE.is_file():
        return ([], [])
    text = ANDROID_APP_GRADLE.read_text(encoding="utf-8")
    dep_rx = re.compile(
        r'^\s*(implementation|debugImplementation|testImplementation|androidTestImplementation)\(\s*(?:platform\(\s*)?"([^"]+)"\s*\)?\s*\)',
        re.M,
    )
    rows: list[dict] = []
    unknown: list[str] = []
    seen: set[tuple[str, str]] = set()
    for match in dep_rx.finditer(text):
        scope, coord = match.group(1), match.group(2)
        if (scope, coord) in seen:
            continue
        seen.add((scope, coord))
        matched_lic = ""
        matched_url = ""
        for rx, lic, url in ANDROID_DECLARED_LICENSES:
            if rx.search(coord):
                matched_lic = lic
                matched_url = url
                break
        if not matched_lic:
            unknown.append(f"{scope}: {coord}")
        rows.append(
            {
                "scope": scope,
                "coord": coord,
                "license": matched_lic or "UNDECLARED",
                "url": matched_url,
            }
        )
    rows.sort(key=lambda r: (r["scope"], r["coord"]))
    return (rows, unknown)


def verify_minih264_header() -> None:
    if not MINIH264_HEADER.is_file():
        raise RuntimeError(f"missing vendored header: {MINIH264_HEADER}")
    head = "\n".join(
        MINIH264_HEADER.read_text(encoding="utf-8", errors="replace").splitlines()[:12]
    )
    if "creativecommons.org/publicdomain/zero/1.0" not in head:
        raise RuntimeError(
            f"{MINIH264_HEADER} header no longer matches expected CC0-1.0 dedication"
        )


def render() -> tuple[str, int, int, list[str]]:
    verify_minih264_header()
    meta = cargo_metadata()
    workspace = set(meta.get("workspace_members") or [])
    first_party = []
    third_party = []
    undeclared = []
    git_sources = []
    for pkg in meta["packages"]:
        name = pkg["name"]
        version = pkg["version"]
        ident = f"{name} {version}"
        license_id = (pkg.get("license") or "").strip()
        license_file = (pkg.get("license_file") or "").strip()
        repository = (pkg.get("repository") or "").strip()
        source = (pkg.get("source") or "").strip()
        row = {
            "name": name,
            "version": version,
            "license": license_id,
            "license_file": license_file,
            "repository": repository,
            "source": source,
            "id": pkg.get("id") or ident,
        }
        if pkg.get("id") in workspace:
            first_party.append(row)
            continue
        if source and not source.startswith("registry+"):
            git_sources.append(row)
        if license_id or license_file:
            third_party.append(row)
        else:
            undeclared.append(row)

    def key(row: dict) -> tuple[str, str]:
        return (row["name"].lower(), row["version"])

    first_party.sort(key=key)
    third_party.sort(key=key)
    undeclared.sort(key=key)
    git_sources.sort(key=key)

    android_rows, android_unknown = parse_android_gradle_deps()

    lines: list[str] = []
    lines.append("# Third-party licenses")
    lines.append("")
    lines.append("Generated by `scripts/generate-third-party-licenses.py` from")
    lines.append("`cargo metadata --format-version 1 --offline --locked`,")
    lines.append("in-tree vendored sources/assets, and `android/app/build.gradle.kts`.")
    lines.append("Do not edit this file by hand; re-run the script after a")
    lines.append("lockfile, asset, or Android dependency change. License identifiers")
    lines.append("are copied from each package's declared metadata or upstream")
    lines.append("LICENSE file without guessing.")
    lines.append("")
    lines.append(f"Workspace members: {len(first_party)}.")
    lines.append(
        f"Third-party Rust crates with a declared license or license-file: {len(third_party)}."
    )
    lines.append(
        f"Third-party Rust crates with no license field in cargo metadata: {len(undeclared)}."
    )
    lines.append(
        f"Declared Android Gradle dependencies (`android/app/build.gradle.kts`): {len(android_rows)}."
    )
    lines.append("")
    lines.append("## First-party workspace crates")
    lines.append("")
    lines.append("Licensed as declared in the workspace (`MIT OR Apache-2.0`).")
    lines.append("See `LICENSE-MIT`, `LICENSE-APACHE`, and `NOTICE`.")
    lines.append("")
    for row in first_party:
        declared = row["license"] or "(workspace license; crate metadata license field empty)"
        lines.append(f"- `{row['name']} {row['version']}` — {declared}")
    lines.append("")
    if git_sources:
        lines.append("## Pinned non-crates.io Rust sources")
        lines.append("")
        lines.append(
            "These packages are pinned by full commit SHA in `Cargo.toml` and `Cargo.lock`:"
        )
        lines.append("")
        for row in git_sources:
            lines.append(
                f"- `{row['name']} {row['version']}` — {row['license']} (`{row['source']}`)"
            )
        lines.append("")
    lines.append("## Vendored C/header sources and embedded assets")
    lines.append("")
    lines.append(
        "- `crates/agentlink-desktop/vendor/minih264e.h` (`https://github.com/lieff/minih264`) —"
    )
    lines.append(
        "  Public domain dedication (`CC0-1.0`, `http://creativecommons.org/publicdomain/zero/1.0/`),"
    )
    lines.append("  compiled via `crates/agentlink-desktop/src/stream/native/minih264_glue.c`.")
    lines.append("- `crates/agentlink-cli/assets/Inter-Regular.ttf`,")
    lines.append("  `Inter-Medium.ttf`, `Inter-SemiBold.ttf` — SIL Open Font")
    lines.append("  License 1.1, in `crates/agentlink-cli/assets/Inter-LICENSE.txt`.")
    lines.append("- `crates/agentlink-cli/assets/JetBrainsMono-Regular.ttf` —")
    lines.append(
        "  SIL Open Font License 1.1, in `crates/agentlink-cli/assets/JetBrainsMono-OFL.txt`."
    )
    lines.append(
        "- `epaint_default_fonts 0.31.1` fallback fonts (pulled via `eframe` `default_fonts`:"
    )
    lines.append(
        "  `Ubuntu-Light.ttf` under Ubuntu Font Licence 1.0, `NotoEmoji-Regular.ttf` under"
    )
    lines.append(
        "  SIL Open Font License 1.1, `Hack-Regular.ttf` under MIT + Bitstream Vera + public"
    )
    lines.append(
        "  domain, and `emoji-icon-font.ttf` under MIT) — verbatim upstream license texts in"
    )
    lines.append("  `crates/agentlink-cli/assets/epaint-default-fonts-LICENSES.txt`.")
    lines.append("- `crates/agentlink-cli/assets/agentlink-octopus.svg`,")
    lines.append("  `agentlink.ico`, and `docs/*.svg` — first-party workspace")
    lines.append("  files covered by the workspace license.")
    lines.append("- Noto Sans CJK is not bundled. The Controller may load a")
    lines.append(
        "  system or drop-in copy at runtime; see `crates/agentlink-cli/src/controller/fonts.rs`."
    )
    lines.append("")
    lines.append("## Codec copyright vs. patent notice (`openh264`)")
    lines.append("")
    lines.append(
        "The Rust crates `openh264` and `openh264-sys2` compile OpenH264 C/C++ source code"
    )
    lines.append(
        "under the `BSD-2-Clause` copyright license (`https://github.com/cisco/openh264/blob/master/LICENSE`)."
    )
    lines.append(
        "Compiling OpenH264 from source is distinct from downloading Cisco's prebuilt binary"
    )
    lines.append(
        "module; this inventory records source copyright licenses only and does not provide"
    )
    lines.append(
        "a patent license or legal advice. Parties distributing compiled binaries should"
    )
    lines.append(
        "assess AVC/H.264 patent licensing requirements applicable to their distribution."
    )
    lines.append("")
    lines.append("## Declared Android Gradle dependencies (`android/app/build.gradle.kts`)")
    lines.append("")
    lines.append(
        "For dual-licensed `net.java.dev.jna:jna` (`Apache-2.0 OR LGPL-2.1-or-later`),"
    )
    lines.append(
        "Agentlink elects the `Apache-2.0` option for JNA's own code (bundled native"
    )
    lines.append("components inside JNA retain their upstream notices).")
    lines.append("")
    lines.append("| Scope | Artifact | Upstream License | Upstream |")
    lines.append("| --- | --- | --- | --- |")
    for row in android_rows:
        lines.append(
            f"| `{row['scope']}` | `{row['coord']}` | {row['license']} | {row['url']} |"
        )
    lines.append("")
    lines.append("## Third-party Rust crates (from Cargo.lock / cargo metadata)")
    lines.append("")
    lines.append("| Crate | Version | License (cargo metadata) | Repository |")
    lines.append("| --- | --- | --- | --- |")
    for row in third_party:
        license_str = row["license"] or f"license-file: {row['license_file']}"
        repo = row["repository"] or ""
        lines.append(
            f"| `{row['name']}` | {row['version']} | {license_str} | {repo} |"
        )
    lines.append("")
    lines.append("## Third-party crates with no license in cargo metadata")
    lines.append("")
    if undeclared:
        lines.append("The generator did not invent a license for these crates.")
        lines.append("")
        for row in undeclared:
            extra = []
            if row["repository"]:
                extra.append(row["repository"])
            if row["license_file"]:
                extra.append("license-file=" + row["license_file"])
            suffix = f" ({'; '.join(extra)})" if extra else ""
            lines.append(f"- `{row['name']} {row['version']}`{suffix}")
    else:
        lines.append("None. Every third-party crate in this lockfile declared a")
        lines.append("`license` or `license-file` field in cargo metadata.")
    lines.append("")

    return ("\n".join(lines) + "\n", len(third_party), len(undeclared), android_unknown)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify THIRD_PARTY.md is up to date without modifying it.",
    )
    args = parser.parse_args()

    rendered, count_tp, count_undeclared, android_unknown = render()
    if android_unknown:
        print(
            f"error: undeclared Android Gradle dependencies: {android_unknown}",
            file=sys.stderr,
        )
        return 1
    if count_undeclared > 0:
        print(
            f"error: {count_undeclared} Cargo crate(s) have no license metadata",
            file=sys.stderr,
        )
        return 1

    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.is_file() else ""
        if current != rendered:
            print(
                "error: THIRD_PARTY.md is out of date; run: python3 scripts/generate-third-party-licenses.py",
                file=sys.stderr,
            )
            return 1
        print(
            f"ok: {OUT} matches Cargo.lock, vendored sources, and Android Gradle ({count_tp} crates)",
            file=sys.stderr,
        )
        return 0

    OUT.write_text(rendered, encoding="utf-8")
    print(
        f"wrote {OUT} ({count_tp} third-party crates, {count_undeclared} undeclared)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
