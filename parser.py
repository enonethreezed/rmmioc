#!/usr/bin/env python3
"""Extrae los dominios de conexión cloud asociados a herramientas RMM.

Lee el catálogo de LOLRMM (https://github.com/magicsword-io/LOLRMM), recorre los
ficheros YAML bajo ``yaml/`` y extrae los dominios de la sección
``Artifacts.Network[].Domains``.

Por defecto se descartan los dominios "genéricos" (comodín sobre el dominio raíz
del proveedor, p. ej. ``*.anydesk.com``) y se conservan únicamente los endpoints
concretos que la herramienta usa en la nube para conectar (relays, APIs, agentes,
etc.). Los valores que contienen patrones regex/comodín se reducen a su parte
estática.

Salida: una lista plana de dominios (uno por línea) apta para Pi-hole, AdGuard,
uBlock, NextDNS, etc.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

import yaml

try:
    import tldextract
except ImportError:  # pragma: no cover
    tldextract = None

LOLRMM_REPO = "https://github.com/magicsword-io/LOLRMM.git"
CACHE_DIR = Path(".cache/LOLRMM")
DEFAULT_OUTPUT = Path("blocklist/rmm-domains.txt")

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
PLACEHOLDER_RE = re.compile(r"^<.*>$")
SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
STRICT_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
HEADER = """\
# RMM connection domains blocklist
# Source: {source}
# Generated: {generated}
# Total domains: {count}
"""


def is_ipv4(domain: str) -> bool:
    if not IPV4_RE.match(domain):
        return False
    return all(0 <= int(octet) <= 255 for octet in domain.split("."))


def normalize_domain(raw: object) -> str | None:
    """Limpia un valor de dominio: esquema, puerto, ruta, IPs y placeholders."""
    if not isinstance(raw, str):
        return None
    d = raw.strip().strip('"').strip("'")
    if not d:
        return None
    if PLACEHOLDER_RE.match(d):
        return None
    d = SCHEME_RE.sub("", d)
    d = d.split("/", 1)[0]
    if d.startswith("["):
        return None  # IPv6 entre corchetes
    if d.count(":") == 1:
        host, port = d.rsplit(":", 1)
        if port.isdigit():
            d = host
        else:
            return None  # IPv6 sin corchetes
    d = d.lower().strip(".")
    if not d or is_ipv4(d) or ":" in d or " " in d:
        return None
    return d


def reduce_domain(domain: str) -> tuple[str | None, bool]:
    """Devuelve (dominio_estático, tenía_comodín_raíz).

    Elimina el ``*.`` inicial y descarta las etiquetas dinámicas (regex/comodín)
    quedándonos con la parte estática del dominio.
    """
    had_wildcard = False
    while domain.startswith("*."):
        had_wildcard = True
        domain = domain[2:]
    labels = [lbl for lbl in domain.split(".") if lbl]
    static = [lbl for lbl in labels if STRICT_LABEL_RE.match(lbl)]
    if not static:
        return None, had_wildcard
    return ".".join(static), had_wildcard


def is_generic(domain: str, had_wildcard: bool, extract) -> bool:
    """True si es un comodín sobre el dominio raíz del proveedor (``*.vendor.tld``)."""
    if not had_wildcard:
        return False
    if tldextract is None or extract is None:
        return len(domain.split(".")) <= 2
    return not extract(domain).subdomain


def iter_network_domains(yaml_dir: Path):
    """Recorre los YAML y produce los valores crudos de ``Artifacts.Network.Domains``."""
    files = sorted(yaml_dir.glob("*.y*ml"))
    for f in files:
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8", errors="replace"))
        except yaml.YAMLError as exc:
            print(f"  [skip] {f.name}: {exc}", file=sys.stderr)
            continue
        if not isinstance(data, dict):
            continue
        artifacts = data.get("Artifacts") or {}
        for entry in artifacts.get("Network") or []:
            if isinstance(entry, dict):
                for dom in entry.get("Domains") or []:
                    yield f.name, dom


def parse_catalog(yaml_dir: Path, include_generic: bool, include_website: bool):
    """Procesa el catálogo y devuelve (específicos, genéricos)."""
    yaml_dir = Path(yaml_dir)
    extract = None
    if tldextract is not None:
        try:
            extract = tldextract.TLDExtract(suffix_list_urls=None)
        except Exception:  # pragma: no cover
            extract = None

    specific: set[str] = set()
    generic: set[str] = set()
    total = 0

    for fname, raw in iter_network_domains(yaml_dir):
        total += 1
        domain = normalize_domain(raw)
        if domain is None:
            continue
        reduced, had_wildcard = reduce_domain(domain)
        if reduced is None:
            continue
        if is_generic(reduced, had_wildcard, extract):
            generic.add(reduced)
        else:
            specific.add(reduced)

    if include_website:
        for f in sorted(yaml_dir.glob("*.y*ml")):
            try:
                data = yaml.safe_load(f.read_text(encoding="utf-8", errors="replace"))
            except yaml.YAMLError:
                continue
            if not isinstance(data, dict):
                continue
            details = data.get("Details") or {}
            website = details.get("Website") if isinstance(details, dict) else None
            domain = normalize_domain(website)
            if domain:
                reduced, had_wildcard = reduce_domain(domain)
                if reduced:
                    specific.add(reduced)

    if include_generic:
        specific |= generic

    return specific, generic, total


def write_blocklist(output: Path, domains: set[str], source: str, generated: str):
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    ordered = sorted(domains)
    with output.open("w", encoding="utf-8") as fh:
        fh.write(
            HEADER.format(
                source=source, generated=generated, count=len(ordered)
            )
        )
        fh.write("\n")
        fh.write("\n".join(ordered))
        fh.write("\n")
    return ordered


def sync_repo(repo_dir: Path, repo_url: str, shallow: bool = True):
    repo_dir = Path(repo_dir)
    if (repo_dir / ".git").exists():
        subprocess.run(
            ["git", "-C", str(repo_dir), "pull", "--ff-only"],
            check=True,
            capture_output=True,
            text=True,
        )
    else:
        repo_dir.parent.mkdir(parents=True, exist_ok=True)
        cmd = ["git", "clone"]
        if shallow:
            cmd += ["--depth", "1"]
        cmd += [repo_url, str(repo_dir)]
        subprocess.run(cmd, check=True, capture_output=True, text=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        default=None,
        help="Directorio de LOLRMM ya clonado (evita el git clone/pull).",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="Fichero de salida (por defecto %(default)s).",
    )
    parser.add_argument(
        "--include-generic",
        action="store_true",
        help="Incluye también los dominios raíz genéricos (``*.vendor.tld``).",
    )
    parser.add_argument(
        "--include-website",
        action="store_true",
        help="Incluye el dominio de Details.Website de cada herramienta.",
    )
    parser.add_argument(
        "--no-sync",
        action="store_true",
        help="No clonar/actualizar LOLRMM; usar la caché local.",
    )
    parser.add_argument(
        "--repo-url",
        default=LOLRMM_REPO,
        help="URL del repositorio LOLRMM (por defecto %(default)s).",
    )
    args = parser.parse_args(argv)

    if args.source:
        source_dir = Path(args.source)
    else:
        source_dir = CACHE_DIR
        if not args.no_sync:
            sync_repo(source_dir, args.repo_url)

    yaml_dir = source_dir / "yaml"
    if not yaml_dir.is_dir():
        print(f"error: no existe {yaml_dir}", file=sys.stderr)
        return 1

    specific, generic, total = parse_catalog(
        yaml_dir,
        include_generic=args.include_generic,
        include_website=args.include_website,
    )

    from datetime import datetime, timezone

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    ordered = write_blocklist(args.output, specific, args.repo_url, generated)

    print(f"Entradas Network procesadas: {total}")
    print(f"Dominios de conexión (específicos): {len(ordered)}")
    print(f"Dominios genéricos descartados: {len(generic)}")
    print(f"Escrito en: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
