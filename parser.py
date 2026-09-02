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

Antes de escribir la lista, cada dominio se valida con una consulta de registro A
(``dig A``); los dominios que no existen (NXDOMAIN) se descartan para no incluir
endpoints muertos. Con ``--drop-nodata`` también se descartan los que existen pero
no tienen registro A.

Salida: una lista plana de dominios (uno por línea) apta para Pi-hole, AdGuard,
uBlock, NextDNS, etc.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

try:
    import tldextract
except ImportError:  # pragma: no cover
    tldextract = None

try:
    import dns.resolver
except ImportError:  # pragma: no cover
    dns = None

LOLRMM_REPO = "https://github.com/magicsword-io/LOLRMM.git"
CACHE_DIR = Path(".cache/LOLRMM")
DEFAULT_OUTPUT = Path("blocklist/rmm-domains.txt")
DEFAULT_IPS_OUTPUT = Path("blocklist/rmm-ips.txt")
DEFAULT_REVIEW_OUTPUT = Path("blocklist/rmm-domains-review.txt")

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
PLACEHOLDER_RE = re.compile(r"^<.*>$")
SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
STRICT_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")

# Dominios apex de plataformas multi-tenant muy usadas para hosting/distribución
# genérica (no específicas de RMM). Si una herramienta referencia uno de estos
# dominios (o un subdominio suyo) el hostname se aparta a la lista de revisión:
# bloquearlo a nivel DNS afecta a tráfico legítimo no relacionado con el RMM.
SHARED_PLATFORM_DOMAINS = {
    "github.com",
    "githubusercontent.com",
    "sourceforge.net",
    "amazonaws.com",
    "google.com",
    "googleusercontent.com",
    "microsoft.com",
    "live.com",
    "cloudflare.com",
    "dropbox.com",
    "npmjs.com",
    "pypi.org",
    "digitaloceanspaces.com",
}

HEADER = """\
# RMM connection domains blocklist
# Source: {source}
# Generated: {generated}
# Total domains: {count}
# DNS check: A record{extra}
"""

IP_HEADER = """\
# RMM connection IPs (non-domain endpoints)
# Source: {source}
# Generated: {generated}
# Total IPs: {count}
# Not DNS-blockable: use at the firewall/proxy (destination IP ACL) layer.
"""

REVIEW_HEADER = """\
# RMM domains requiring manual review before blocking
# Source: {source}
# Generated: {generated}
# Total domains: {count}
#
# These hostnames sit on shared multi-tenant platforms (GitHub, AWS, Google,
# Microsoft, etc.). The exact FQDN is tied to one RMM tool, but its parent
# domain hosts unrelated legitimate traffic — blocking the FQDN wholesale
# (or generalizing it to the parent domain) risks large collateral damage.
# Confirm scope before adding these to a DNS or web-traffic blocklist.
"""


def lookup_a(domain: str, timeout: float, retries: int = 2) -> str:
    """Resuelve el registro A de ``domain`` y devuelve su estado.

    Estados: ``A`` (tiene registro A), ``NODATA`` (el dominio existe pero sin A),
    ``NXDOMAIN`` (el dominio no existe) y ``ERROR`` (fallo transitorio).
    """
    for _ in range(retries):
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        try:
            resolver.resolve(domain, "A")
            return "A"
        except dns.resolver.NXDOMAIN:
            return "NXDOMAIN"
        except dns.resolver.NoAnswer:
            return "NODATA"
        except Exception:
            continue
    return "ERROR"


def filter_by_dns(domains: set[str], timeout: float, workers: int, drop_nodata: bool):
    """Descarta los dominios sin resolución A (NXDOMAIN, y opcionalmente NODATA)."""
    if dns is None:
        return domains, {}

    dropped: dict[str, str] = {}
    keep: set[str] = set()

    def _check(domain: str) -> tuple[str, str]:
        return domain, lookup_a(domain, timeout)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for domain, status in pool.map(_check, sorted(domains)):
            if status == "NXDOMAIN":
                dropped[domain] = status
            elif status == "NODATA" and drop_nodata:
                dropped[domain] = status
            else:
                keep.add(domain)

    return keep, dropped


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


def is_shared_platform(domain: str) -> bool:
    """True si ``domain`` es (o cuelga de) una plataforma multi-tenant genérica."""
    return any(
        domain == apex or domain.endswith("." + apex) for apex in SHARED_PLATFORM_DOMAINS
    )


def iter_network_entries(yaml_dir: Path):
    """Recorre los YAML y produce ``(tool_name, raw_value)`` por cada dominio/IP en
    ``Artifacts.Network.Domains``. ``tool_name`` es el campo ``Name`` del YAML (o el
    nombre de fichero como fallback) para poder atribuir cada endpoint a su herramienta."""
    files = sorted(yaml_dir.glob("*.y*ml"))
    for f in files:
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8", errors="replace"))
        except yaml.YAMLError as exc:
            print(f"  [skip] {f.name}: {exc}", file=sys.stderr)
            continue
        if not isinstance(data, dict):
            continue
        tool_name = data.get("Name") or f.name
        artifacts = data.get("Artifacts") or {}
        for entry in artifacts.get("Network") or []:
            if isinstance(entry, dict):
                for dom in entry.get("Domains") or []:
                    yield tool_name, dom


def parse_catalog(yaml_dir: Path, include_generic: bool, include_website: bool, include_review: bool):
    """Procesa el catálogo y devuelve (específicos, genéricos, revisión, ips, atribución, total)."""
    yaml_dir = Path(yaml_dir)
    extract = None
    if tldextract is not None:
        try:
            extract = tldextract.TLDExtract(suffix_list_urls=None)
        except Exception:  # pragma: no cover
            extract = None

    specific: set[str] = set()
    generic: set[str] = set()
    review: set[str] = set()
    ips: set[str] = set()
    attribution: dict[str, set[str]] = {}
    total = 0

    def attribute(key: str, tool_name: str) -> None:
        attribution.setdefault(key, set()).add(tool_name)

    for tool_name, raw in iter_network_entries(yaml_dir):
        total += 1
        candidate = raw.strip().strip('"').strip("'") if isinstance(raw, str) else None
        if candidate and is_ipv4(candidate):
            ips.add(candidate)
            attribute(candidate, tool_name)
            continue
        domain = normalize_domain(raw)
        if domain is None:
            continue
        reduced, had_wildcard = reduce_domain(domain)
        if reduced is None:
            continue
        attribute(reduced, tool_name)
        if is_shared_platform(reduced):
            review.add(reduced)
        elif is_generic(reduced, had_wildcard, extract):
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
            tool_name = data.get("Name") or f.name
            details = data.get("Details") or {}
            website = details.get("Website") if isinstance(details, dict) else None
            domain = normalize_domain(website)
            if domain:
                reduced, had_wildcard = reduce_domain(domain)
                if reduced:
                    attribute(reduced, tool_name)
                    if is_shared_platform(reduced):
                        review.add(reduced)
                    else:
                        specific.add(reduced)

    if include_generic:
        specific |= generic
    if include_review:
        specific |= review
        review = set()

    return specific, generic, review, ips, attribution, total


def write_blocklist(output: Path, domains: set[str], source: str, generated: str, dns_extra: str = ""):
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    ordered = sorted(domains)
    with output.open("w", encoding="utf-8") as fh:
        fh.write(
            HEADER.format(
                source=source, generated=generated, count=len(ordered), extra=dns_extra
            )
        )
        fh.write("\n")
        fh.write("\n".join(ordered))
        fh.write("\n")
    return ordered


def write_ip_list(output: Path, ips: set[str], source: str, generated: str):
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    ordered = sorted(ips, key=lambda ip: tuple(int(o) for o in ip.split(".")))
    with output.open("w", encoding="utf-8") as fh:
        fh.write(IP_HEADER.format(source=source, generated=generated, count=len(ordered)))
        fh.write("\n")
        fh.write("\n".join(ordered))
        fh.write("\n")
    return ordered


def write_review_list(
    output: Path, domains: set[str], attribution: dict[str, set[str]], source: str, generated: str
):
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    ordered = sorted(domains)
    with output.open("w", encoding="utf-8") as fh:
        fh.write(REVIEW_HEADER.format(source=source, generated=generated, count=len(ordered)))
        fh.write("\n")
        for domain in ordered:
            tools = ", ".join(sorted(attribution.get(domain, set()))) or "unknown"
            fh.write(f"# tools: {tools}\n{domain}\n")
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
        "--include-review",
        action="store_true",
        help=(
            "Incluye en la lista principal los dominios que cuelgan de plataformas "
            "multi-tenant (GitHub, AWS, Google, ...). Por defecto se apartan a "
            "--output-review para revisión manual por el riesgo de sobre-bloqueo."
        ),
    )
    parser.add_argument(
        "--output-ips",
        default=str(DEFAULT_IPS_OUTPUT),
        help="Fichero de salida para IPs literales (por defecto %(default)s).",
    )
    parser.add_argument(
        "--output-review",
        default=str(DEFAULT_REVIEW_OUTPUT),
        help="Fichero de salida para dominios pendientes de revisión (por defecto %(default)s).",
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
    parser.add_argument(
        "--no-dns",
        action="store_true",
        help="No comprobar la resolución A de los dominios.",
    )
    parser.add_argument(
        "--drop-nodata",
        action="store_true",
        help="Descarta también los dominios que existen pero sin registro A (NODATA).",
    )
    parser.add_argument(
        "--dns-timeout",
        type=float,
        default=3.0,
        help="Timeout por consulta DNS en segundos (por defecto %(default)s).",
    )
    parser.add_argument(
        "--dns-workers",
        type=int,
        default=32,
        help="Número de consultas DNS en paralelo (por defecto %(default)s).",
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

    specific, generic, review, ips, attribution, total = parse_catalog(
        yaml_dir,
        include_generic=args.include_generic,
        include_website=args.include_website,
        include_review=args.include_review,
    )

    dropped: dict[str, str] = {}
    dns_extra = ""
    if not args.no_dns:
        if dns is None:
            print("aviso: dnspython no instalado; se omite la comprobación DNS", file=sys.stderr)
            dns_extra = " (skipped: dnspython missing)"
        else:
            specific, dropped = filter_by_dns(
                specific,
                timeout=args.dns_timeout,
                workers=args.dns_workers,
                drop_nodata=args.drop_nodata,
            )
            dns_extra = " (dropped NXDOMAIN)" if not args.drop_nodata else " (dropped NXDOMAIN+NODATA)"

    from datetime import datetime, timezone

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    ordered = write_blocklist(args.output, specific, args.repo_url, generated, dns_extra)
    ip_ordered = write_ip_list(args.output_ips, ips, args.repo_url, generated)
    review_ordered = write_review_list(
        args.output_review, review, attribution, args.repo_url, generated
    )

    print(f"Entradas Network procesadas: {total}")
    print(f"Dominios de conexión (específicos): {len(ordered)}")
    print(f"Dominios genéricos descartados: {len(generic)}")
    print(f"Dominios pendientes de revisión (plataformas compartidas): {len(review_ordered)}")
    print(f"IPs de conexión: {len(ip_ordered)}")
    if dropped:
        counts = Counter(dropped.values())
        for status, n in sorted(counts.items()):
            print(f"Dominios descartados por DNS ({status}): {n}")
    print(f"Escrito en: {args.output}, {args.output_ips}, {args.output_review}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
