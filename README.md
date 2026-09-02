# rmmioc

Lista de bloqueo con los dominios e IPs de conexión cloud asociados a herramientas RMM
(Remote Monitoring and Management), extraída de [LOLRMM](https://github.com/magicsword-io/LOLRMM).

El parser `parser.py` recorre los ficheros YAML del catálogo LOLRMM y extrae los endpoints de
`Artifacts.Network[].Domains`, quedándose con los endpoints concretos de conexión (relays,
APIs, agentes, etc.) y descartando los comodines genéricos sobre el dominio raíz del proveedor
(p. ej. `*.anydesk.com`).

Antes de escribir la lista, cada dominio se valida con una consulta de registro A (`dig A`);
los dominios que no existen (NXDOMAIN) se descartan para no incluir endpoints muertos.

Además:

- Las entradas que son IPs literales (no dominios) — algunas herramientas fijan IPs de relay
  en vez de un hostname — se extraen a un fichero aparte, pensado para bloqueo a nivel de
  firewall/proxy (capa IP), ya que un bloqueo DNS no las cubre.
- Las entradas que cuelgan de plataformas multi-tenant genéricas (GitHub, AWS, Google,
  Microsoft, ...) se apartan a una lista de revisión manual en vez de incluirse sin más:
  bloquear esos hostnames a nivel DNS puede tener colateral desproporcionado sobre tráfico
  legítimo no relacionado con el RMM. Cada entrada indica qué herramienta(s) la referencian.

## Uso

```bash
pip install -r requirements.txt
python3 parser.py            # clona/actualiza LOLRMM y genera los ficheros de blocklist/
python3 parser.py --source /ruta/a/LOLRMM   # usa un checkout local
make update                  # equivalente a `python3 parser.py`
```

### Opciones

| Flag | Descripción |
| --- | --- |
| `--source DIR` | Usa un checkout local de LOLRMM (evita git clone/pull) |
| `--output FILE` | Fichero de salida de dominios (por defecto `blocklist/rmm-domains.txt`) |
| `--output-ips FILE` | Fichero de salida de IPs (por defecto `blocklist/rmm-ips.txt`) |
| `--output-review FILE` | Fichero de dominios pendientes de revisión (por defecto `blocklist/rmm-domains-review.txt`) |
| `--include-generic` | Incluye también los dominios raíz genéricos (`*.vendor.tld`) |
| `--include-website` | Incluye el dominio de `Details.Website` |
| `--include-review` | Incluye en la lista principal los dominios de plataformas compartidas (usar con cautela) |
| `--no-sync` | No clonar/actualizar; usar la caché `.cache/LOLRMM` |
| `--no-dns` | No comprobar la resolución A de los dominios |
| `--drop-nodata` | Descarta también los dominios que existen pero sin registro A (NODATA) |
| `--dns-timeout SEC` | Timeout por consulta DNS (por defecto 3s) |
| `--dns-workers N` | Consultas DNS en paralelo (por defecto 32) |

## Salida

- `blocklist/rmm-domains.txt`: lista plana (un dominio por línea), compatible con Pi-hole,
  AdGuard, uBlock, NextDNS, etc. — bloqueo a nivel DNS.
- `blocklist/rmm-ips.txt`: IPs literales de relays RMM sin hostname asociado — para ACLs de
  firewall/proxy (bloqueo a nivel de tráfico de red, no DNS-blockable).
- `blocklist/rmm-domains-review.txt`: dominios sobre plataformas multi-tenant (GitHub, AWS,
  Google, Microsoft...) con la(s) herramienta(s) que los usan; requieren confirmación manual
  antes de añadirse a cualquier lista de bloqueo por el riesgo de sobre-bloqueo.

## Mantenimiento

El workflow de GitHub Actions (`.github/workflows/update-blocklist.yml`) regenera la lista
cada lunes y hace commit automático de los cambios.
