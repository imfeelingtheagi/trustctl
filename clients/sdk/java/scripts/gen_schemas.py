#!/usr/bin/env python3
"""Generate the Java OpenAPI schema index from clients/sdk/openapi.json."""

import json
import sys
from pathlib import Path


def java_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: gen_schemas.py <openapi.json> <OpenApiSchemas.java>", file=sys.stderr)
        return 2
    spec_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    spec = json.loads(spec_path.read_text())
    schemas = sorted((spec.get("components") or {}).get("schemas") or {})
    body = [
        "package com.trstctl.sdk;",
        "",
        "import java.util.List;",
        "",
        "/**",
        " * Generated from clients/sdk/openapi.json by clients/sdk/java/scripts/gen_schemas.py.",
        " * This index gives Java builds a cheap drift signal even though the supported",
        " * runtime keeps hand-written dependency-free resource helpers.",
        " */",
        "public final class OpenApiSchemas {",
        "  private OpenApiSchemas() {}",
        "",
        "  public static final List<String> NAMES = List.of(",
    ]
    for idx, name in enumerate(schemas):
        comma = "," if idx < len(schemas) - 1 else ""
        body.append(f"      {java_string(name)}{comma}")
    body.extend(
        [
            "  );",
            "}",
            "",
        ]
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(body))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
