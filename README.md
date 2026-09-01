# rmmioc

Lista de bloqueo con los dominios de conexión cloud asociados a herramientas RMM
(Remote Monitoring and Management), extraída de [LOLRMM](https://github.com/magicsword-io/LOLRMM).

El parser `parser.py` recorre los ficheros YAML del catálogo LOLRMM y extrae los dominios de
`Artifacts.Network[].Domains`, quedándose con los endpoints concretos de conexión (relays,
APIs, agentes, etc.) y descartando los comodines genéricos sobre el dominio raíz del proveedor
(p. ej. `*.anydesk.com`).

Antes de escribir la lista, cada dominio se valida con una consulta de registro A (`dig A`);
los dominios que no existen (NXDOMAIN) se descartan para no incluir endpoints muertos.

## Uso

```bash
pip install -r requirements.txt
python3 parser.py            # clona/actualiza LOLRMM y genera blocklist/rmm-domains.txt
python3 parser.py --source /ruta/a/LOLRMM   # usa un checkout local
make update                  # equivalente a `python3 parser.py`
```

### Opciones

| Flag | Descripción |
| --- | --- |
| `--source DIR` | Usa un checkout local de LOLRMM (evita git clone/pull) |
| `--output FILE` | Fichero de salida (por defecto `blocklist/rmm-domains.txt`) |
| `--include-generic` | Incluye también los dominios raíz genéricos (`*.vendor.tld`) |
| `--include-website` | Incluye el dominio de `Details.Website` |
| `--no-sync` | No clonar/actualizar; usar la caché `.cache/LOLRMM` |
| `--no-dns` | No comprobar la resolución A de los dominios |
| `--drop-nodata` | Descarta también los dominios que existen pero sin registro A (NODATA) |
| `--dns-timeout SEC` | Timeout por consulta DNS (por defecto 3s) |
| `--dns-workers N` | Consultas DNS en paralelo (por defecto 32) |

## Salida

`blocklist/rmm-domains.txt` es una lista plana (un dominio por línea), compatible con
Pi-hole, AdGuard, uBlock, NextDNS, etc.

## Mantenimiento

El workflow de GitHub Actions (`.github/workflows/update-blocklist.yml`) regenera la lista
cada lunes y hace commit automático de los cambios.
