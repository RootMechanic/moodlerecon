#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MoodleRecon - Scanner de seguridad para Moodle (un solo fichero)
=================================================================
Combina y mejora las tecnicas de scanner.py (hashes + advisories de
moodle.org) y moodlescan.py (interseccion de hashes, proxy, headers),
anadiendo tecnicas actuales: OSV.dev (GHSA), fingerprint multi-evidencia,
enumeracion de plugins/temas, baseline anti-falso-positivo y chequeos de
mala configuracion. Pensado SOLO para auditorias autorizadas:
Los GET recogen evidencias. El acceso invitado usa POST; las pruebas de
recuperacion/alta son opcionales y la recuperacion puede enviar correos.

Uso:
  python moodlerecon.py --url https://moodle.example.com
  python moodlerecon.py --url https://moodle.example.com --scan -v
  python moodlerecon.py --update

Opciones utiles: --threads --timeout --proxy -k(insecure) -v --no-enum
Requisitos: requests (pip install requests). Opcional: cvss para CVSS 4 (CVSS 3 se calcula sin dependencias adicionales).
Exploit-DB: --exploitdb RUTA permite consultar files_exploits.csv tambien en Windows.
Informe: --report informe.json. --version X.Y.Z requiere verificacion del auditor.
"""

import argparse
import concurrent.futures as cf
import csv
import hashlib
import secrets
from html.parser import HTMLParser
from http.cookiejar import MozillaCookieJar
import json
import os
import re
import sys
import time
import shutil
import subprocess
from html import unescape
from pathlib import Path
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    sys.exit("[-] Falta 'requests'. Instala con: python -m pip install -r requirements.txt")

# ----------------------------------------------------------------------
# Constantes
# ----------------------------------------------------------------------
TOOL = "MoodleRecon/2.2"
GITHUB_TAGS_API = "https://api.github.com/repos/moodle/moodle/tags"
GITHUB_RAW = "https://raw.githubusercontent.com/moodle/moodle/{tag}{path}"
MOODLE_SEC_PAGE = "https://moodle.org/security/index.php"
OSV_QUERY_API = "https://api.osv.dev/v1/query"
OSV_PACKAGE = {"name": "moodle/moodle", "ecosystem": "Packagist"}

DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".moodlerecon")
HASH_DB = os.path.join(DB_DIR, "hashes.txt")       # path;md5;tag
VULN_DB = os.path.join(DB_DIR, "vulns.csv")        # CSV scrapeado de moodle.org
META_DB = os.path.join(DB_DIR, "meta.json")

# Archivos estaticos usados para fingerprint de version por hash.
# min_tag: rama minima en la que el archivo existe (comparacion semantica,
# corrige el bug de comparacion por strings del script original).
HASH_FILES = [
    ("/lib/upgrade.txt", "2.1"),
    ("/composer.json", "2.4"),
    ("/question/upgrade.txt", "2.5"),
    ("/composer.lock", "2.9"),
    ("/privacy/export_files/general.js", "3.5"),
    ("/admin/environment.xml", None),
    ("/admin/tool/lp/tests/behat/course_competencies.feature", "3.6"),
]

# Plugins de terceros frecuentes (no core) a sondear via version.php.
PROBE_PLUGINS = [
    "mod/hvp", "mod/bigbluebuttonbn", "mod/attendance", "mod/checklist",
    "mod/customcert", "mod/questionnaire", "mod/turnitintooltwo",
    "mod/offlinequiz", "mod/scheduler", "mod/certificate", "mod/forumng",
    "mod/jitsi", "mod/zoom", "mod/wooclap", "mod/h5pactivity_custom",
    "block/configurable_reports", "block/quickmail", "block/checklist",
    "block/rubrics", "local/ombiel", "local/mobile", "local/wunderbyte_table",
    "auth/saml2", "enrol/ltiprovider",
    "theme/adaptable", "theme/moove", "theme/fordson", "theme/boost_campus",
    "theme/klass", "theme/trema", "theme/eguru",
]

# Rutas sensibles: (ruta, validador regex, severidad, descripcion)
EXPOSED_PATHS = [
    ("/admin/environment.xml", r"<environment|MOODLE_VERSION", "INFO",
     "environment.xml contiene requisitos de versiones, no la configuracion real del servidor"),
    ("/composer.json", r'"require"', "LOW",
     "composer.json accesible (lista de dependencias)"),
    ("/composer.lock", r'"packages"', "MEDIUM",
     "composer.lock accesible (versiones exactas de dependencias)"),
    ("/.git/HEAD", r"ref: refs/", "HIGH",
     "Repositorio .git expuesto: el codigo fuente puede ser descargable"),
    ("/config.php~", r"\$CFG", "HIGH",
     "Backup de config.php accesible: puede exponer credenciales de BD"),
    ("/config.php.swp", r"\$CFG", "HIGH",
     "Fichero temporal de config.php accesible"),
        ("/README.md", r"[Mm]oodle", "LOW", "README.md expone informacion del despliegue"),
    ("/phpinfo.php", r"phpinfo\(\)|PHP Version", "MEDIUM", "phpinfo() expuesto"),
]

SEC_HEADERS = ["strict-transport-security", "content-security-policy",
               "x-frame-options", "x-content-type-options",
               "referrer-policy"]

# Soporte de ramas (fin de soporte de seguridad). Fuente: moodledev.io /
# endoflife.date (actualizable con --update).
BUILTIN_EOL = {
    "3.11": "2023-11-13", "3.9": "2023-11-13", "4.0": "2023-11-13",
    "5.2": "2027-04-19", "5.1": "2027-04-19", "5.0": "2026-10-05",
    "4.5": "2027-10-04", "4.4": "2026-04-21", "4.3": "2025-10-05",
    "4.2": "2025-04-21", "4.1": "2025-10-05",
}

SEV_COLOR = {"CRITICAL": "\033[91;1m", "HIGH": "\033[91m", "MEDIUM": "\033[93m",
             "LOW": "\033[94m", "INFO": "\033[96m"}
RESET, GREEN, STYLE_RESET = "\033[0m", "\033[92m", "\033[0m"
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ----------------------------------------------------------------------
# Utilidades de versiones (comparacion semantica, no por strings)
# ----------------------------------------------------------------------
def parse_version(v):
    """'v4.5.14+' -> (4, 5, 14). Devuelve None si no es parseable."""
    m = re.fullmatch(r"v?(\d+)(?:\.(\d+))?(?:\.(\d+))?\+?", (v or "").strip())
    if not m:
        return None
    return tuple(int(g) if g is not None else 0 for g in m.groups())


def cmp_version(a, b):
    pa, pb = parse_version(a), parse_version(b)
    if pa is None or pb is None:
        return 0
    return (pa > pb) - (pa < pb)


def version_in_affected(detected, affected):
    """
    Evalua cadenas del estilo moodle.org:
      '5.2 to 5.2.2, 5.1 to 5.1.6, 4.5 to 4.5.13 and earlier unsupported versions'
      '5.0' (solo 5.0.0) | '5.0 to 5.0.9 and earlier unsupported versions'
    True si la version detectada cae dentro de algun rango afectado.
    """
    if parse_version(detected) is None or not affected:
        return False
    txt = unescape(affected).lower().replace("+", " ").strip()
    earlier = "earlier unsupported" in txt
    txt = txt.replace("earlier unsupported versions", "")
    parts = re.split(r",|\band\b", txt)
    branch_starts = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        mm = re.match(r"^([\d.]+)\s*to\s*([\d.]+)$", part)
        if mm:
            lo, hi = mm.group(1), mm.group(2)
            branch_starts.append(parse_version(lo))
            if cmp_version(detected, lo) >= 0 and cmp_version(detected, hi) <= 0:
                return True
        else:
            m2 = re.match(r"^([\d.]+)$", part)
            if m2:
                v = m2.group(1)
                branch_starts.append(parse_version(v))
                dv, vv = parse_version(detected), parse_version(v)
                if dv and vv:
                    # Un lanzamiento X.Y equivale a X.Y.0, no a toda su rama.
                    if dv == vv:
                        return True
    if earlier and branch_starts:
        dv = parse_version(detected)
        if dv and dv < min(branch_starts):
            return True
    return False


# ----------------------------------------------------------------------
# Cliente HTTP con sesion, retries, cache y manejo de errores
# ----------------------------------------------------------------------
class HttpClient:
    """Get con cache, reintentos ante 429 y errores controlados.
    Cada chequeo recibe un objeto resultado y nunca lanza excepciones."""

    def __init__(self, timeout=10, proxy=None, verify=True, verbose=False):
        self.timeout, self.verbose = timeout, verbose
        self.cache = {}
        s = requests.Session()
        retry = Retry(total=2, backoff_factor=0.8,
                      status_forcelist=(500, 502, 503, 504),
                      allowed_methods=frozenset(["GET", "HEAD"]))
        s.mount("http://", HTTPAdapter(max_retries=retry, pool_connections=10))
        s.mount("https://", HTTPAdapter(max_retries=retry, pool_connections=10))
        s.headers["User-Agent"] = f"{TOOL} (+authorized-security-audit)"
        if proxy:
            s.proxies = {"http": proxy, "https": proxy}
        s.verify = verify
        self.session = s

    def get(self, url):
        if url in self.cache:
            return self.cache[url]
        result = None
        for attempt in range(3):
            try:
                r = self.session.get(url, timeout=self.timeout,
                                     allow_redirects=True)
                if r.status_code == 429:                      # rate limit
                    try:
                        wait = max(0, float(r.headers.get("Retry-After", 2 * (attempt + 1))))
                    except ValueError:
                        wait = 2 * (attempt + 1)
                    self._log(f"429 en {url}, esperando {wait:.0f}s")
                    time.sleep(min(wait, 30))
                    continue
                result = r
                break
            except requests.exceptions.SSLError as e:
                return self._err(url, f"SSL: {e}")
            except requests.exceptions.ProxyError as e:
                return self._err(url, f"Proxy: {e}")
            except requests.exceptions.ConnectTimeout as e:
                return self._err(url, f"Timeout de conexion: {e}")
            except requests.exceptions.ReadTimeout:
                if attempt == 2:
                    return self._err(url, "Timeout de lectura")
            except requests.exceptions.ConnectionError as e:
                return self._err(url, f"Conexion: {e}")
            except requests.exceptions.RequestException as e:
                return self._err(url, str(e))
        if result is None:
            return self._err(url, "Limite de peticiones agotado (429)")
        self.cache[url] = result
        return result

    def _err(self, url, msg):
        self._log(f"Error {url}: {msg}")
        r = requests.models.Response()
        r.status_code = 0
        r._content = b""
        r.url = url
        self.cache[url] = r
        return r

    def _log(self, msg):
        if self.verbose:
            print(f"    [http] {msg}")


class Finding:
    def __init__(self, severity, title, detail="", evidence="",
                 reference="", confidence="INFO"):
        self.severity, self.title = severity, title
        self.detail, self.evidence = detail, evidence
        self.reference, self.confidence = reference, confidence

    def show(self):
        color = SEV_COLOR.get(self.severity, "")
        print(f"\n{color}[{self.severity}] {self.title} ({self.confidence}){RESET}")
        for label, val in (("", self.detail), ("Evidence: ", self.evidence),
                           ("Reference: ", self.reference)):
            if val:
                print(f"  {label}{val}" if label else f"  {val}")


# ----------------------------------------------------------------------
# --update: base de datos de hashes (incremental) y de vulnerabilidades
# ----------------------------------------------------------------------
def load_meta():
    if os.path.exists(META_DB):
        try:
            return json.load(open(META_DB))
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def save_meta(meta):
    os.makedirs(DB_DIR, exist_ok=True)
    with open(META_DB, "w") as f:
        json.dump(meta, f, indent=1)


def fetch_all_tags(client):
    tags, page = [], 1
    while True:
        r = client.get(f"{GITHUB_TAGS_API}?page={page}&per_page=100")
        if r.status_code != 200:
            print(f"[-] GitHub API respondio {r.status_code}")
            return None
        try:
            batch = [t["name"] for t in r.json()]
        except (ValueError, TypeError, KeyError):
            return None
        tags.extend(batch)
        link = r.headers.get("Link", "")
        if 'rel="next"' in link and batch:
            page += 1
            time.sleep(0.3)
        else:
            break
    return tags


def hash_remote_file(tag, path, client):
    r = client.get(GITHUB_RAW.format(tag=tag, path=path))
    if r.status_code == 200 and r.content:
        return f"{path};{hashlib.md5(r.content).hexdigest()};{tag}"
    if r.status_code != 404:
        raise RuntimeError(f"Descarga incompleta: {tag} {path} ({r.status_code})")
    return None


def update_hash_db(client, threads):
    """Actualizacion INCREMENTAL: solo calcula hashes de tags nuevos.
    (Corrige el bug del original, que re-descargaba todo o no creaba la BD)."""
    meta = load_meta()
    known = set(meta.get("tags", [])) if os.path.exists(HASH_DB) else set()
    tags = fetch_all_tags(client)
    if tags is None:
        return False
    # Ignora tags que no son releases estables de Moodle (vX.Y...)
    tags = [t for t in tags if re.fullmatch(r"v\d+\.\d+(?:\.\d+)?", t)]
    new_tags = [t for t in tags if t not in known]
    if not new_tags:
        print(f"[+] BD de hashes al dia ({len(known)} tags).")
        return True
    print(f"[+] {len(new_tags)} tags nuevos de {len(tags)}. Descargando hashes...")
    jobs = []
    for tag in new_tags:
        tv = parse_version(tag)
        for path, min_tag in HASH_FILES:
            if min_tag and tv and tv < parse_version(min_tag):
                continue
            jobs.append((tag, path))
    lines, done, failed_tags = [], 0, set()
    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(hash_remote_file, t, p, client): (t, p)
                for t, p in jobs}
        for fut in cf.as_completed(futs):
            try:
                line = fut.result()
            except Exception:
                failed_tags.add(futs[fut][0])
                line = None
            done += 1
            if done % 200 == 0:
                print(f"    {done}/{len(jobs)} ficheros")
            if line:
                lines.append(line)
    os.makedirs(DB_DIR, exist_ok=True)
    existing = set(Path(HASH_DB).read_text().splitlines()) if os.path.exists(HASH_DB) else set()
    lines = sorted(set(lines) - existing)
    with open(HASH_DB, "a") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))
    meta["tags"] = sorted(known | (set(new_tags) - failed_tags))
    save_meta(meta)
    print(f"[+] BD actualizada: {len(lines)} hashes; {len(failed_tags)} tags incompletos se reintentaran.")
    return not failed_tags


def update_vuln_db(client):
    """Scraping de https://moodle.org/security/ (como scanner.py, pero con
    sesion/UA propios y sin romper si una pagina falla)."""
    rows, page, ua_backup = [], 0, client.session.headers["User-Agent"]
    complete, seen = True, set()
    client.session.headers["User-Agent"] = "MoodleRecon-SecurityFeed"  # moodle.org bloquea el UA python-requests
    while True:
        url = f"{MOODLE_SEC_PAGE}?o=3&s=10&p={page}"
        try:
            r = client.session.get(url, timeout=client.timeout)
        except requests.RequestException as e:
            print(f"[-] Error en pagina {page}: {e}")
            complete = False
            break
        if r.status_code != 200:
            complete = False
            break
        digest = hashlib.sha256(r.content).hexdigest()
        if digest in seen or page >= 200:
            complete = False
            break
        seen.add(digest)
        found = re.findall(
            r"<td[^>]*>\s*(?:<[^>]+>\s*)*(Severity/Risk|Versions affected|"
            r"Versions fixed|CVE identifier|Tracker issue)", r.text)
        if not found:
            break
        # Extraccion robusta de las tablas de advisories
        for tbl in re.findall(r"<table.*?</table>", r.text, re.S):
            info = {}
            for tr in re.findall(r"<tr.*?</tr>", tbl, re.S):
                cols = re.findall(r"<td[^>]*>(.*?)</td>", tr, re.S)
                if len(cols) == 2:
                    label = unescape(re.sub(r"<[^>]+>", "", cols[0])).strip()
                    value = unescape(re.sub(r"<[^>]+>", "", cols[1])).strip()
                    for key in ("Severity/Risk", "Versions affected",
                                "Versions fixed", "CVE identifier",
                                "Tracker issue"):
                        if key.lower() in label.lower():
                            info[key] = value
            if info:
                rows.append([info.get("Severity/Risk", ""),
                             info.get("Versions affected", ""),
                             info.get("Versions fixed", ""),
                             info.get("CVE identifier", ""),
                             info.get("Tracker issue", "")])
        if not rows or (page and len(rows) == prev_count):
            break
        prev_count, page = len(rows), page + 1
        time.sleep(0.4)
    client.session.headers["User-Agent"] = ua_backup
    if not rows or not complete:
        print("[-] Actualizacion incompleta; se conserva el CSV anterior. No se extrajo ninguna vulnerabilidad de moodle.org.")
        return False
    os.makedirs(DB_DIR, exist_ok=True)
    with open(VULN_DB + ".tmp", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Severity/Risk", "Versions Affected", "Versions Fixed",
                    "CVE Identifier", "Tracker Issue"])
        w.writerows(rows)
    os.replace(VULN_DB + ".tmp", VULN_DB)
    print(f"[+] {len(rows)} advisories guardados en {VULN_DB}")
    return True


# ----------------------------------------------------------------------
# Deteccion de Moodle (multi-evidencia, sin fiarse de un solo 200)
# ----------------------------------------------------------------------
def fingerprint_moodle(client, base):
    evidence = []
    r = client.get(base + "/")
    if r.status_code == 0:
        return None, ["Sin conexion con el objetivo"]
    html = r.text
    if "MoodleSession" in (r.headers.get("Set-Cookie", "") or ""):
        evidence.append("Cookie MoodleSession en la respuesta")
    if re.search(r"name=[\"']logintoken[\"']", html):
        evidence.append("Campo logintoken (formulario de login Moodle)")
    if re.search(r"/theme/(styles|image|javascript)\.php", html):
        evidence.append("URLs de tema Moodle (theme/styles.php)")
    if re.search(r"/lib/(javascript-static|requirejs|jquery)", html):
        evidence.append("Recursos estaticos tipicos de Moodle en el HTML")
    lr = client.get(base + "/login/index.php")
    if lr.status_code == 200 and re.search(r"name=[\"']logintoken[\"']", lr.text):
        evidence.append("login/index.php con formulario Moodle")
    return (r, lr), evidence


def detect_themes_plugins_from_html(client, base, html):
    """Tema activo y plugins EN USO extraidos del HTML real (no por 200)."""
    themes = sorted(set(re.findall(r"/theme/([a-z][a-z0-9_]+)/", html)))
    plugins = sorted(set(re.findall(r"/(mod|blocks?|local|auth|enrol|filter|report)/([a-z0-9_]+)/", html)))
    return themes, plugins


# ----------------------------------------------------------------------
# Deteccion de version: interseccion de candidatos por hash
# ----------------------------------------------------------------------
def load_hash_db():
    db = {}
    if not os.path.exists(HASH_DB):
        return db
    with open(HASH_DB) as f:
        for line in f:
            parts = line.strip().split(";")
            if len(parts) == 3:
                db.setdefault(parts[0], {}).setdefault(parts[1], set()).add(parts[2].lstrip("v"))
    return db


def detect_version(client, base, threads):
    """Devuelve (version, confianza, detalle). Estrategia:
    1. Hashes MD5 de ficheros estaticos + INTERSECCION de candidatos por
       fichero (mejora la logica de moodlescan sobre la de scanner.py).
    2. Fallback: parseo de cabeceras '=== X.Y.Z ===' en /lib/upgrade.txt.
    """
    db = load_hash_db()
    client.version_candidates = []
    base = base.rstrip("/")
    target_hashes = {}

    def fetch(path):
        r = client.get(base + path)
        if r.status_code == 200 and r.content and r.url == base + path:
            return path, hashlib.md5(r.content).hexdigest()
        return path, None

    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        for path, h in ex.map(fetch, [p for p, _ in HASH_FILES]):
            target_hashes[path] = h

    candidate_sets = {}
    for path, h in target_hashes.items():
        if h and path in db and h in db[path]:
            candidate_sets[path] = db[path][h]

    if candidate_sets:
        common = set.intersection(*candidate_sets.values())
        client.version_candidates = sorted(common, key=parse_version)
        if len(common) == 1:
            v = common.pop()
            return v, "CONFIRMADA" if len(candidate_sets) >= 2 else "PROBABLE", \
                f"Interseccion de hashes de {len(candidate_sets)} ficheros: {sorted(candidate_sets)}"
        if common:
            return None, "AMBIGUA", \
                f"Candidatos comunes a todos los ficheros: {sorted(common)}"
        return None, "CONFLICTIVA", "Hashes incompatibles: posible despliegue modificado o mixto"

    # Fallback: ultima cabecera de upgrade.txt (como badmoodle, nivel 1)
    for path in ("/lib/upgrade.txt", "/question/upgrade.txt"):
        r = client.get(base + path)
        if r.status_code == 200:
            heads = re.findall(r"^==+\s*([\d.]+)\s*==+", r.text, re.M)
            if heads:
                v = sorted(heads, key=parse_version)[-1]
                return ".".join(v.split(".")[:2]), "ESTIMADA (rama)", \
                    f"Cabecera de {path}: la version exacta requiere --update"
    return None, "DESCONOCIDA", "Sin hashes coincidentes ni upgrade.txt accesible"


# ----------------------------------------------------------------------
# Enumeracion de plugins por version.php con baseline anti-soft-404
# ----------------------------------------------------------------------
def enumerate_plugins(client, base, threads):
    """Sondea version.php de plugins comunes. Un 200 solo NO basta:
    exige cuerpo pequeno/vacio (PHP sin salida) y distinto del baseline."""
    base = base.rstrip("/")
    bl = client.get(base + "/mod/zzz_no_such_plugin_xyz/version.php")
    baseline = (bl.status_code, len(bl.content or b""))
    found = []

    def probe(path):
        r = client.get(f"{base}/{path}/version.php")
        ok = r.url == f"{base}/{path}/version.php" and (r.status_code == 200 and len(r.content or b"") < 64
              and (r.status_code, len(r.content or b"")) != baseline
              or (r.status_code == 200 and baseline[0] == 404
                  and len(r.content or b"") < 64))
        return path if ok else None

    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        for p in ex.map(probe, PROBE_PLUGINS):
            if p:
                found.append(p)
    return sorted(found)


# ----------------------------------------------------------------------
# Vulnerabilidades: OSV.dev (GHSA) en vivo + CSV local como respaldo
# ----------------------------------------------------------------------
def cvss3_base(vector):
    """CVSS 3.0/3.1 base segun FIRST; no requiere dependencias externas."""
    if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        raise ValueError("Vector CVSS 3 no valido")
    pairs = [part.split(":") for part in vector.split("/")[1:]]
    if any(len(pair) != 2 for pair in pairs) or len({k for k, _ in pairs}) != len(pairs):
        raise ValueError("Metricas duplicadas o invalidas")
    metrics = dict(pairs)
    if metrics.get("S") not in ("U", "C"):
        raise ValueError("Scope no valido")
    changed = metrics["S"] == "C"
    try:
        av = {"N": .85, "A": .62, "L": .55, "P": .2}[metrics["AV"]]
        ac = {"L": .77, "H": .44}[metrics["AC"]]
        pr = {"N": .85, "L": .68 if changed else .62, "H": .5 if changed else .27}[metrics["PR"]]
        ui = {"N": .85, "R": .62}[metrics["UI"]]
        c, i, a = ({"N": 0, "L": .22, "H": .56}[metrics[key]] for key in ("C", "I", "A"))
    except KeyError as e:
        raise ValueError("Metrica base ausente o invalida") from e
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    score = min((impact + 8.22 * av * ac * pr * ui) * (1.08 if changed else 1), 10)
    # FIRST Appendix A: redondear a 5 decimales antes de Roundup.
    integer = int(round(score * 100000))
    return integer / 100000 if integer % 10000 == 0 else (integer // 10000 + 1) / 10


def severity_from_score(n):
    return "CRITICAL" if n >= 9 else "HIGH" if n >= 7 else "MEDIUM" if n >= 4 else "LOW" if n > 0 else "INFO"


def severity_from_osv(v):
    named = str(v.get("database_specific", {}).get("severity", "")).upper()
    named = {"MODERATE": "MEDIUM"}.get(named, named)
    severities = [named] if named in SEV_ORDER else []
    for entry in v.get("severity", []):
        score = str(entry.get("score", ""))
        try:
            if score.startswith(("CVSS:3.0/", "CVSS:3.1/")):
                n = cvss3_base(score)
            elif score.startswith("CVSS:4."):
                from cvss import CVSS4
                n = CVSS4(score).scores()[0]
            else:
                n = float(score)
            if 0 <= float(n) <= 10:
                severities.append(severity_from_score(float(n)))
        except Exception:
            continue
    return min(severities, key=lambda value: SEV_ORDER[value]) if severities else "INFO"


PDFTEX_ADVISORY = {
    "id": "CVE-2024-43426", "severity": "HIGH",
    "affected": "4.4 to 4.4.1, 4.3 to 4.3.5, 4.2 to 4.2.8, 4.1 to 4.1.11 and earlier unsupported versions",
    "fixed": "4.4.2, 4.3.6, 4.2.9 and 4.1.12",
    "summary": "Arbitrary file read risk through pdfTeX",
    "reference": "https://moodle.org/security/index.php?o=3&p=13&s=10",
    "conditions": "Requiere filtro TeX habilitado y pdfTeX disponible. Comprobar configuracion y posibles parches locales. Mitigacion: deshabilitar el filtro TeX.",
}


# Avisos esenciales incorporados: cobertura minima sin CSV/OSV, no catalogo completo.
# Riesgo del fabricante y CVSS externo se muestran por separado.
BUILTIN_ADVISORIES = [PDFTEX_ADVISORY, {
    "id": "CVE-2023-30944", "severity": "HIGH", "vendor_risk": "Minor",
    "score": 7.3, "score_reference": "https://www.tenable.com/plugins/was/114761",
    "affected": "4.1 to 4.1.2, 4.0 to 4.0.7, 3.11 to 3.11.13, 3.9 to 3.9.20 and earlier unsupported versions",
    "fixed": "4.1.3, 4.0.8, 3.11.14 and 3.9.21",
    "summary": "SQL injection limitada en el metodo externo Wiki de listado de paginas",
    "reference": "https://moodle.org/security/index.php?o=3&p=20&s=10",
    "conditions": "Comprobar actividad Wiki, disponibilidad del metodo externo mod_wiki_get_page_list y permisos de acceso. Solo correlacion por version; no se ha ejecutado SQLi.",
}, {
    "id": "CVE-2023-40317", "severity": "HIGH", "vendor_risk": "Serious",
    "affected": "4.2 to 4.2.1, 4.1 to 4.1.4, 4.0 to 4.0.9, 3.11 to 3.11.15, 3.9 to 3.9.22 and earlier unsupported versions",
    "fixed": "4.2.2, 4.1.5, 4.0.10, 3.11.16 and 3.9.23",
    "summary": "RCE al analizar referencias de repositorios de ficheros malformadas",
    "reference": "https://moodle.org/security/index.php?o=3&p=19&s=10",
    "conditions": "Verificar repositorios disponibles, acceso a referencias de ficheros y precondiciones del aviso; no se ha probado explotabilidad.",
}, {
    "id": "CVE-2023-5550", "severity": "CRITICAL", "vendor_risk": "Serious",
    "score": 9.8, "score_reference": "https://www.tenable.com/cve/CVE-2023-5550",
    "affected": "4.2 to 4.2.2, 4.1 to 4.1.5, 4.0 to 4.0.10, 3.11 to 3.11.16, 3.9 to 3.9.23 and earlier unsupported versions",
    "fixed": "4.2.3, 4.1.6, 4.0.11, 3.11.17 and 3.9.24",
    "summary": "RCE por LFI en hosting compartido mal configurado",
    "reference": "https://moodle.org/security/index.php?o=3&p=17&s=10",
    "conditions": "Requiere hosting compartido mal configurado y usuario Moodle con acceso directo al servidor fuera del webroot. Esos requisitos no se verifican remotamente.",
}, {
    "id": "CVE-2023-28334", "severity": "LOW", "vendor_risk": "Minor",
    "affected": "4.1 to 4.1.1 and 4.0 to 4.0.6", "fixed": "4.1.2 and 4.0.7",
    "summary": "Enumeracion de nombres mediante IDOR en planes de aprendizaje",
    "reference": "https://moodle.org/security/index.php?o=3&p=20&s=10",
    "conditions": "Requiere usuario autenticado; no afecta a 3.11 segun el aviso oficial.",
}]


def affected_status(version, affected):
    if not version_in_affected(version, affected):
        return "NO_AFECTADA"
    text = unescape(affected).lower()
    starts = [parse_version(x) for x in re.findall(r"(?<![\d.])\d+\.\d+(?:\.\d+)?", text)]
    if "earlier unsupported" in text and starts and parse_version(version) < min(starts):
        return "REQUIERE_REVISION (rama antigua sin soporte)"
    return "POTENCIAL (rango de version; configuracion sin verificar)"


def query_osv(version, client=None):
    session = client.session if client else requests.Session()
    try:
        r = session.post(OSV_QUERY_API, timeout=client.timeout if client else 15,
                         json={"version": version, "package": OSV_PACKAGE})
        if r.status_code != 200:
            return None
        out = []
        for v in r.json().get("vulns", []):
            if v.get("withdrawn"):
                continue
            aliases = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
            out.append({"id": "; ".join(aliases) or v.get("id", "?"),
                        "severity": severity_from_osv(v),
                        "summary": v.get("summary", "(sin resumen)"),
                        "reference": f"https://osv.dev/vulnerability/{v.get('id', '')}",
                        "confidence": "POTENCIAL (OSV; configuracion sin verificar)",
                        "evidence": f"OSV devuelve coincidencia para {version}; no se ha probado explotabilidad"})
        return out
    except (requests.RequestException, ValueError, TypeError, AttributeError):
        return None


def correlate_vulns(version, client):
    """Cruza ambas fuentes; el rango oficial prevalece si existe."""
    remote = query_osv(version, client)
    records = {v["id"]: v for v in (remote or [])}
    official = [dict(item) for item in BUILTIN_ADVISORIES]
    if os.path.exists(VULN_DB):
        with open(VULN_DB, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                ids = re.findall(r"CVE-\d{4}-\d+", row.get("CVE Identifier", ""))
                raw = row.get("Severity/Risk", "").lower()
                sev = "HIGH" if "serious" in raw else "CRITICAL" if "critical" in raw else "LOW" if "minor" in raw else "INFO"
                for identifier in ids:
                    official.append({"id": identifier, "severity": sev,
                        "affected": row.get("Versions Affected", ""),
                        "fixed": row.get("Versions Fixed", ""),
                        "summary": row.get("Tracker Issue", identifier),
                        "reference": MOODLE_SEC_PAGE})
    builtins = {item["id"]: item for item in BUILTIN_ADVISORIES}
    for item in official:
        if not item["affected"]:
            continue
        # El aviso incorporado conserva tambien sus precondiciones.
        if item["id"] in builtins:
            item = dict(builtins[item["id"]])
        previous = next((record for key, record in records.items() if item["id"] in key.split("; ")), {})
        item["severity"] = min((item["severity"], previous.get("severity", "INFO")), key=lambda value: SEV_ORDER.get(value, 9))
        for key in list(records):
            if item["id"] in key.split("; "):
                records.pop(key)
        status = affected_status(version, item["affected"])
        if status == "NO_AFECTADA":
            continue
        item["confidence"] = status
        item["evidence"] = f"Version: {version}; rango oficial: {item['affected']}; corregido: {item['fixed']}"
        item["summary"] += ". " + item.get("conditions", "Verificar requisitos del aviso y posibles parches locales.")
        if item.get("vendor_risk"):
            item["evidence"] += "; riesgo Moodle: " + item["vendor_risk"]
        if item.get("score"):
            item["evidence"] += f"; CVSS externo: {item['score']} ({item['score_reference']})"
        records[item["id"]] = item
    complete = remote is not None or os.path.exists(VULN_DB)
    return list(records.values()), complete


def correlate_candidates(candidates, client):
    """Union de avisos; conserva si coinciden todos o solo algunos candidatos."""
    versions = sorted(set(candidates), key=parse_version)
    if not versions:
        return [], False
    records, coverage = {}, True
    for version in versions[:20]:
        items, complete = correlate_vulns(version, client)
        coverage = coverage and complete
        for item in items:
            record = records.setdefault(item["id"], dict(item, matching_versions=[]))
            record["matching_versions"].append(version)
            record["severity"] = min((record["severity"], item["severity"]), key=lambda value: SEV_ORDER[value])
    for item in records.values():
        matches = item["matching_versions"]
        label = "TODOS" if len(matches) == len(versions) else "ALGUNOS"
        item["confidence"] = f"POTENCIAL ({label} los candidatos de version; precondiciones sin verificar)"
        item["evidence"] += f"; candidatos: {', '.join(versions)}; coinciden: {', '.join(matches)}"
    return list(records.values()), coverage and len(versions) <= 20


def run_local(argv, timeout=15):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                          encoding="utf-8", errors="replace", shell=False,
                          env=dict(os.environ, LC_ALL="C"))


def exploitdb_status(root, args):
    """APT se compara con APT; un CSV diferente de GitLab no prueba antiguedad."""
    if not root:
        return "DESCONOCIDO: no se localizo el indice CSV para comprobar su origen"
    if shutil.which("dpkg-query") and shutil.which("apt-cache"):
        try:
            owner = run_local(["dpkg-query", "-S", str(root / "files_exploits.csv")])
            if owner.returncode == 0 and re.search(r"^exploitdb(?::[^: ]+)?:", owner.stdout, re.M):
                policy = run_local(["apt-cache", "policy", "exploitdb"])
                installed = re.search(r"^\s*Installed:\s*(\S+)", policy.stdout, re.M)
                candidate = re.search(r"^\s*Candidate:\s*(\S+)", policy.stdout, re.M)
                if policy.returncode == 0 and installed and candidate and "(none)" not in (installed[1], candidate[1]):
                    if installed[1] == candidate[1]:
                        return f"ACTUALIZADA PARA APT ({installed[1]}; segun cache de repositorios configurados). GitLab tiene otro canal; refrescar cache con sudo apt update para verificar cambios recientes."
                    comparison = run_local(["dpkg", "--compare-versions", installed[1], "lt", candidate[1]])
                    if comparison.returncode == 0:
                        return f"ACTUALIZACION APT DISPONIBLE: instalada {installed[1]}, candidata {candidate[1]}. Ejecutar searchsploit -u."
                    if comparison.returncode == 1:
                        return f"VERSION APT LOCAL SUPERIOR/DISTINTA: instalada {installed[1]}, candidata {candidate[1]}; no se afirma que este desactualizada."
                return "DESCONOCIDO (paquete APT): no se pudo leer instalada/candidata; ejecutar sudo apt update y searchsploit -u para comprobar."
        except (OSError, subprocess.TimeoutExpired):
            return "DESCONOCIDO: fallo al consultar APT"
    try:
        session = HttpClient(timeout=args.timeout, proxy=args.proxy, verify=not args.insecure).session
        metadata = session.head(
            "https://gitlab.com/api/v4/projects/exploit-database%2Fexploitdb/repository/files/files_exploits.csv?ref=HEAD",
            timeout=args.timeout, allow_redirects=True)
        remote_hash = metadata.headers.get("X-Gitlab-Content-Sha256", "")
        if metadata.status_code == 200 and re.fullmatch(r"[a-fA-F0-9]{64}", remote_hash):
            local_hash = hashlib.sha256((root / "files_exploits.csv").read_bytes()).hexdigest()
            if local_hash == remote_hash.lower():
                return "ACTUALIZADA (indice CSV coincide con GitLab oficial)"
            return "INDICE DISTINTO DE GITLAB (antiguedad no determinada). Revisar canal/origen; si es clon Git, actualizar con git pull --ff-only."
    except (OSError, requests.RequestException):
        pass
    return "DESCONOCIDO: no se pudo verificar el indice remoto; comprobar con searchsploit -u segun el canal de instalacion"


def searchsploit_findings(args):
    """Consulta referencias locales; nunca ejecuta exploits ni actualiza paquetes."""
    findings = []
    executable = shutil.which("searchsploit")
    candidates = [args.exploitdb] if args.exploitdb else [
        "/usr/share/exploitdb", "/opt/exploit-database", "/opt/exploitdb"]
    root = next((Path(x).resolve() for x in candidates if x and (Path(x) / "files_exploits.csv").is_file()), None)
    if not root and executable:
        candidate = Path(executable).resolve().parent
        if (candidate / "files_exploits.csv").is_file():
            root = candidate
    install = "Kali: sudo apt update && sudo apt install exploitdb. Windows: usar WSL/Kali o --exploitdb RUTA con files_exploits.csv. Guia: https://www.exploit-db.com/searchsploit"
    if not root and not executable:
        print("[!] SearchSploit/Exploit-DB no encontrado. Para ampliar la cobertura: " + install)
        return [Finding("INFO", "SearchSploit/Exploit-DB no disponible", install)]
    print("[*] Consulta local de Exploit-DB (referencias, no vulnerabilidades confirmadas)...")
    status = exploitdb_status(root, args)
    print("    Estado de la base de datos: " + status)
    findings.append(Finding("INFO", "Estado de Exploit-DB", status,
                            reference="https://www.exploit-db.com/searchsploit"))
    try:
        if root:
            with (root / "files_exploits.csv").open(encoding="utf-8-sig", newline="") as f:
                entries = [{"Title": row.get("description", ""), "EDB-ID": row.get("id", ""),
                            "codes": row.get("codes", "")} for row in csv.DictReader(f)
                           if re.search(r"\bmoodle\b", row.get("description", ""), re.I)]
        else:
            result = run_local([executable, "--json", "--disable-colour", "moodle"])
            if result.returncode:
                raise ValueError("SearchSploit devolvio un error")
            entries = json.loads(result.stdout).get("RESULTS_EXPLOIT", [])
        seen_ids = set()
        for row in entries:
            identifier = str(row.get("EDB-ID", ""))
            if not identifier.isdigit() or identifier in seen_ids:
                continue
            seen_ids.add(identifier)
            findings.append(Finding("INFO", "Exploit-DB " + identifier + ": " + row.get("Title", ""),
                "Coincidencia por producto. Revisar version, componente, autenticacion y requisitos del exploit.",
                evidence=row.get("codes", ""), reference="https://www.exploit-db.com/exploits/" + identifier,
                confidence="REFERENCIA (aplicabilidad sin verificar)"))
    except (OSError, ValueError, subprocess.TimeoutExpired, AttributeError):
        findings.append(Finding("INFO", "Consulta Exploit-DB incompleta", "Comprobar instalacion y formato de la base de datos. " + install))
    return findings


def scan_local_vulns(version):
    if not os.path.exists(VULN_DB):
        return None
    out = []
    with open(VULN_DB, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if version_in_affected(version, row.get("Versions Affected", "")):
                sev_raw = (row.get("Severity/Risk") or "").lower()
                sev = ("HIGH" if "serious" in sev_raw or "critical" in sev_raw
                       else "LOW" if "minor" in sev_raw else "MEDIUM")
                out.append({"id": row.get("CVE Identifier") or row.get("Tracker Issue", "?"),
                            "severity": sev,
                            "summary": f"Afecta: {row.get('Versions Affected','')} | "
                                       f"Corregido: {row.get('Versions Fixed','')}",
                            "reference": "https://moodle.org/security/",
                            "confidence": affected_status(version, row.get("Versions Affected", ""))})
    return out


# ----------------------------------------------------------------------
# Chequeos de configuracion insegura e informacion expuesta
# ----------------------------------------------------------------------
def check_exposure(client, base, headers_home):
    findings, base = [], base.rstrip("/")
    baseline = client.get(base + "/__moodlerecon_missing_7f64a8.txt")

    def probe(item):
        path, regex, sev, desc = item
        r = client.get(base + path)
        if (r.status_code == 200 and r.url == base + path
                and r.content != baseline.content and re.search(regex, r.text or "")):
            return Finding(sev, f"Fichero expuesto: {path}", desc,
                           f"GET {path} -> 200 y contenido validado "
                           f"(no basta el codigo de estado)",
                           confidence="CONFIRMADO")
        return None

    with cf.ThreadPoolExecutor(max_workers=6) as ex:
        for f_ in ex.map(probe, EXPOSED_PATHS):
            if f_:
                findings.append(f_)

    # Cabeceras de seguridad ausentes
    missing = [h for h in SEC_HEADERS if not headers_home.get(h)]
    if missing:
        findings.append(Finding(
            "LOW", "Cabeceras de seguridad ausentes",
            "Revisar en el servidor web: " + ", ".join(missing),
            evidence=f"Cabeceras recibidas: {sorted(headers_home)}",
            reference="https://moodledev.io/general/development/policies/security",
            confidence="INFO"))
    # Cookie MoodleSession sin flags
    for cookie in client.session.cookies:
        if cookie.name != "MoodleSession":
            continue
        flags = {str(k).lower() for k in cookie._rest}
        missing_flags = ([] if cookie.secure else ["Secure"]) + ([] if "httponly" in flags else ["HttpOnly"])
        if missing_flags:
            findings.append(Finding("LOW", "Cookie MoodleSession sin " + "/".join(missing_flags),
                evidence="Atributos de cookie observados; valor de sesion omitido", confidence="CONFIRMADO"))
    return findings


def check_misconfig(client, base):
    findings, base = [], base.rstrip("/")
    r = client.get(base + "/login/signup.php")
    if r.status_code == 200:
        if re.search(r"<form[^>]+id=[\"']signup[\"']|name=[\"']signup", r.text) \
           and "signups are disabled" not in r.text.lower():
            findings.append(Finding(
                "INFO", "Formulario de autoregistro visible",
                "Verificar si el autoregistro es intencionado y sus controles; no demuestra que el alta se complete.",
                "/login/signup.php muestra formulario de alta activo",
                confidence="CONFIRMADO"))
    li = client.get(base + "/login/index.php")
    if li.status_code == 200 and re.search(r"Log in as a guest|login as guest|Invitado", li.text):
        findings.append(Finding(
            "INFO", "Texto de acceso invitado visible",
            "El boton de acceso como invitado esta visible en el login.",
            evidence="/login/index.php", confidence="INDICIO (sesion sin verificar)"))
    ws = client.get(base + "/webservice/rest/server.php")
    if ws.status_code == 200 and re.search(r'"errorcode"', ws.text or ""):
        findings.append(Finding(
            "INFO", "Endpoint REST responde",
            "El endpoint REST responde JSON de error sin token: el servicio "
            "puede estar deshabilitado (por ejemplo, webservice_access_exception). Verificar tokens de privilegio limitado y "
            "valid_until, y que login/token.php no permita servicios amplios.",
            evidence=ws.text[:160].strip(),
            reference="https://docs.moodle.org/en/Web_services",
            confidence="CONFIRMADO"))
    home = client.get(base + "/")
    if re.search(r'<[^>]+class=["\'][^"\']*\bdebuggingmessage\b', home.text or ""):
        findings.append(Finding(
            "MEDIUM", "Modo debug activo (debugdisplay)",
            "Los mensajes de depuracion se muestran a los usuarios: riesgo de "
            "fuga de informacion (rutas, consultas, stack traces).",
            evidence="HTML de la portada contiene .debuggingmessage",
            confidence="CONFIRMADO"))
    return findings


class HtmlSurvey(HTMLParser):
    """Extrae enlaces, formularios y textos concretos sin dependencia de bs4."""
    def __init__(self, html):
        super().__init__(convert_charrefs=True)
        self.links, self.forms, self.captures, self.text = [], [], [], []
        self.stack, self.active, self.form, self.ignored = [], [], None, 0
        self.feed(html or "")

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag in ("script", "style"):
            self.ignored += 1
        if self.ignored:
            return
        if tag == "form":
            self.form = dict(attrs, fields={})
            self.forms.append(self.form)
        if tag == "input" and self.form is not None and attrs.get("name"):
            input_type = attrs.get("type", "text").lower()
            if input_type not in ("submit", "button", "reset", "file") and (input_type not in ("checkbox", "radio") or "checked" in attrs):
                self.form["fields"][attrs["name"]] = attrs.get("value", "")
        if tag == "a":
            link = dict(attrs, text="")
            self.links.append(link)
            self.active.append((len(self.stack) + 1, tag, link))
        classes = attrs.get("class", "").split()
        if (tag in ("h1", "h2", "title", "author", "dc:creator")
                or set(classes) & {"logininfo", "usermenu", "userprofile", "page-header-headings"}
                or attrs.get("id", "").startswith("id_error_")):
            capture = dict(attrs, tag=tag, text="")
            self.captures.append(capture)
            self.active.append((len(self.stack) + 1, tag, capture))
        if tag not in ("input", "img", "br", "hr", "meta", "link", "source", "area", "wbr"):
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.ignored = max(0, self.ignored - 1)
            return
        if self.ignored:
            return
        if tag == "form":
            self.form = None
        if tag in self.stack:
            index = len(self.stack) - 1 - self.stack[::-1].index(tag)
            self.stack = self.stack[:index]
            self.active = [entry for entry in self.active if entry[0] <= index]

    def handle_data(self, value):
        if self.ignored:
            return
        self.text.append(value)
        for _, _, entry in self.active:
            entry["text"] += value


def in_scope(base, url):
    expected, actual = urlparse(base), urlparse(url)
    prefix = expected.path.rstrip("/")
    return (actual.scheme in ("http", "https") and actual.scheme == expected.scheme
            and actual.netloc == expected.netloc and not actual.username
            and (not prefix or actual.path == prefix or actual.path.startswith(prefix + "/")))


def scoped_request(client, base, url, method="GET", data=None):
    """No envia formularios, cookies ni tokens a redirecciones fuera del Moodle."""
    for _ in range(6):
        if not in_scope(base, url):
            return None
        try:
            r = client.session.request(method, url, data=data, timeout=client.timeout, allow_redirects=False)
        except requests.RequestException:
            return None
        if r.status_code not in (301, 302, 303, 307, 308):
            return r
        location = r.headers.get("Location")
        if not location:
            return None
        url = urljoin(url, location)
        if r.status_code == 303 or (r.status_code in (301, 302) and method == "POST"):
            method, data = "GET", None
    return None


def safe_source(url):
    parsed = urlparse(url)
    if "/rss/file.php/" in parsed.path:
        return parsed.scheme + "://" + parsed.netloc + parsed.path.split("/rss/file.php/")[0] + "/rss/file.php/[redacted]"
    allowed = {"id", "userid", "course", "courseid", "entryid", "page", "offset", "blogpage", "tagid"}
    query = urlencode({k: v[0] for k, v in parse_qs(parsed.query).items() if k in allowed})
    return parsed._replace(query=query, fragment="").geturl()


def guest_marker(html):
    survey = HtmlSurvey(html)
    for item in survey.captures:
        if set(item.get("class", "").split()) & {"logininfo", "usermenu"}:
            text = " ".join(item["text"].split())
            if re.search(r"logged in as (?:a )?guest|currently using guest access|(?:accediendo|entrado|conectado|iniciado sesi[oó]n).*invitado", text, re.I):
                return True
    return False


def new_audit_client(args):
    return HttpClient(timeout=args.timeout, proxy=args.proxy, verify=not args.insecure, verbose=args.verbose)


def check_guest_login(args, base):
    client = new_audit_client(args)
    login_url = base.rstrip("/") + "/login/index.php?lang=en"
    initial = scoped_request(client, base, login_url)
    reference = "https://docs.moodle.org/en/Guest_access"
    if initial is None:
        client.session.close()
        return None, Finding("INFO", "Acceso invitado no comprobado", "No se pudo obtener el formulario dentro del alcance.", reference=reference)
    survey = HtmlSurvey(initial.text)
    guestform = next((f for f in survey.forms if f.get("id") == "guestlogin" or f["fields"].get("username") == "guest"), None)
    loginform = next((f for f in survey.forms if f.get("id") == "login" or "logintoken" in f["fields"]), None)
    form = guestform or loginform
    if form:
        action = urljoin(initial.url, form.get("action") or initial.url)
        data = {k: v for k, v in form["fields"].items() if k in ("logintoken", "anchor")}
        data.update(username="guest", password="guest")
        result = scoped_request(client, base, action, "POST", data)
        if result is None:
            client.session.close()
            return None, Finding("INFO", "Acceso invitado no comprobado", "Error o redireccion fuera de alcance al enviar el formulario.", reference=reference)
    # Dos GET nuevos: una redireccion o una cookie de sesion no bastan.
    home_url = base.rstrip("/") + "/?lang=en"
    first = scoped_request(client, base, home_url)
    second = scoped_request(client, base, home_url)
    if first is not None and second is not None and guest_marker(first.text) and guest_marker(second.text):
        return client, Finding("INFO", "Inicio de sesion como invitado verificado",
            "La sesion persiste como invitado. No implica acceso a todos los cursos ni es por si solo una vulnerabilidad.",
            evidence="Dos peticiones posteriores muestran el estado invitado en logininfo/usermenu; sin valores de cookies ni tokens.",
            reference=reference, confidence="CONFIRMADO")
    client.session.close()
    return None, Finding("INFO", "Acceso invitado no confirmado",
        "El estado posterior no demuestra una sesion invitada. Puede estar deshabilitado, bloqueado o no reconocerse el tema/idioma.",
        evidence="Formulario invitado visible" if guestform else "No se observo formulario invitado; se comprobo el formulario de login si estaba disponible",
        reference=reference, confidence="INCONCLUSO")


USER_ROUTES = {
    "/course/index.php", "/course/view.php", "/course/category.php",
    "/user/profile.php", "/user/view.php", "/user/index.php",
    "/mod/forum/index.php", "/mod/forum/view.php", "/mod/forum/discuss.php",
    "/blog/index.php", "/calendar/view.php", "/calendar/export.php",
    "/calendar/export_execute.php", "/admin/tool/lp/plans.php",
}


def enumerate_users(client, base, args, context="anonimo"):
    """Perfiles, enlaces de participantes/autores y feeds visibles; recorrido acotado."""
    base = base.rstrip("/")
    prefix = urlparse(base).path.rstrip("/")
    queue = [base + "/", base + "/course/index.php", base + "/blog/index.php", base + "/calendar/view.php"]
    ids = list(range(args.user_id_start, args.user_id_end + 1))
    queue += [base + "/user/profile.php?id=" + str(i) for i in ids]
    if getattr(args, "check_learning_plans", False) and context == "cookies_proporcionadas":
        queue += [base + "/admin/tool/lp/plans.php?userid=" + str(i) + "&lang=en" for i in ids]
    baseline = scoped_request(client, base, base + "/user/profile.php?id=2147483647")
    baseline_hash = hashlib.sha256(baseline.content).hexdigest() if baseline is not None else None
    visited, users, authors = set(), {}, set()
    while queue and len(visited) < args.enum_pages:
        url = queue.pop(0)
        if url in visited or not in_scope(base, url):
            continue
        visited.add(url)
        r = scoped_request(client, base, url)
        if r is None or r.status_code != 200 or not in_scope(base, r.url):
            continue
        if hashlib.sha256(r.content).hexdigest() == baseline_hash:
            continue
        relative = urlparse(r.url).path[len(prefix):]
        if relative.startswith("/login/"):
            continue
        survey = HtmlSurvey(r.text)
        source = safe_source(r.url)
        for link in survey.links:
            href = urljoin(r.url, link.get("href", ""))
            if not in_scope(base, href):
                continue
            parsed = urlparse(href)
            path = parsed.path[len(prefix):]
            params = parse_qs(parsed.query)
            if path in ("/user/profile.php", "/user/view.php"):
                userid = params.get("id", [""])[0]
                name = " ".join(link.get("text", "").split())
                if userid.isdigit() and name and name.lower() not in {"profile", "view profile", "perfil", "ver perfil", "user picture", "imagen del usuario"}:
                    entry = users.setdefault(userid, {"id": int(userid), "display_name": name, "username": None,
                        "emails": [], "sources": [], "access_context": context, "confidence": "NOMBRE_VISIBLE (no demuestra username de login)"})
                    if source not in entry["sources"]:
                        entry["sources"].append(source)
            if ((path in USER_ROUTES or path.startswith("/rss/file.php/"))
                    and href not in visited and href not in queue and len(queue) < args.enum_pages * 3):
                # No seguir cambios de estado ni curso matricula/acciones laterales.
                if not set(params) & {"sesskey", "delete", "edit", "action", "confirm", "subscribe", "unsubscribe"}:
                    queue.append(href.split("#")[0])
        # Perfil real: requiere contenedor userprofile y titulo propio, no basta HTTP 200.
        if relative in ("/user/profile.php", "/user/view.php"):
            userid = parse_qs(urlparse(r.url).query).get("id", [""])[0]
            isprofile = any("userprofile" in item.get("class", "").split() for item in survey.captures)
            heading = next((" ".join(item["text"].split()) for item in survey.captures if item["tag"] == "h1" and item["text"].strip()), "")
            if isprofile and heading and userid.isdigit():
                entry = users.setdefault(userid, {"id": int(userid), "display_name": heading, "username": None,
                    "emails": [], "sources": [], "access_context": context})
                entry.update(display_name=heading, confidence="PERFIL_VISIBLE (username de login desconocido)")
                if source not in entry["sources"]:
                    entry["sources"].append(source)
                entry["emails"] = sorted(set(link.get("href", "")[7:].split("?")[0] for link in survey.links if link.get("href", "").lower().startswith("mailto:")))
        if relative.startswith("/rss/"):
            for item in survey.captures:
                if item["tag"] in ("author", "dc:creator") and item["text"].strip():
                    authors.add((item["text"].strip(), source))
        if relative.endswith("/calendar/export_execute.php") and r.text.startswith("BEGIN:VCALENDAR"):
            for match in re.finditer(r"^ORGANIZER(?:;CN=([^:;\r\n]+))?[^:]*:(?:mailto:)?([^\r\n]+)", r.text, re.M | re.I):
                authors.add(((match[1] or "organizador") + " <" + match[2] + ">", source))
        if args.enum_delay:
            time.sleep(args.enum_delay)
    records = list(users.values())
    records += [{"id": None, "display_name": name, "username": None, "emails": [], "sources": [source],
                 "access_context": context, "confidence": "AUTOR_VISIBLE (identidad de cuenta no verificada)"} for name, source in sorted(authors)]
    finding = Finding("LOW" if records and context == "anonimo" else "INFO", f"Enumeracion de usuarios ({context}): {len(records)} identidad(es) visible(s)",
        "Nombres visibles, IDs y correos publicados no equivalen a usernames de login. Revisar si esta visibilidad es intencionada.",
        evidence=f"{len(visited)} paginas consultadas; limite {args.enum_pages}; IDs {args.user_id_start}-{args.user_id_end}. " +
                 " | ".join(f"ID {entry['id']}: {entry['display_name']}" for entry in records[:10]),
        reference="https://docs.moodle.org/en/Site_security_settings", confidence="OBSERVADO" if records else "SIN_EVIDENCIAS (recorrido limitado)")
    return records, finding


def candidate_accounts(args):
    if not args.usernames:
        return []
    with open(args.usernames, encoding="utf-8-sig") as f:
        out = []
        for line in f:
            value = line.strip()
            if value and not value.startswith("#") and len(value) <= 254 and value not in out:
                out.append(value)
            if len(out) >= args.enum_candidates:
                break
        return out


def recovery_state(html):
    text = " ".join(HtmlSurvey(html).text)
    if re.search(r"if you supplied a correct|si (?:ha |has )?(?:introducido|proporcionado).*correct", text, re.I):
        return "GENERICO"
    if re.search(r"(?:username|email address) was not found|usernamenotfound|emailnotfound|(?:usuario|direcci[oó]n.*correo).*no.*(?:encontr|existe)", text, re.I):
        return "NO_EXISTE"
    if re.search(r"email (?:has been|already) sent|email has already been sent|correo.*(?:ha sido enviado|ya.*enviado)|emailresetconfirmsent|emailalreadysent", text, re.I):
        return "EXISTENCIA_INDICADA"
    return "INCONCLUSO"


def check_account_forms(args, base):
    findings, records = [], []
    if not (args.check_recovery or args.check_signup):
        return records, findings
    candidates = candidate_accounts(args)
    client = new_audit_client(args)
    probes = ["moodlereconmissing" + secrets.token_hex(12)] + candidates
    for kind, enabled, route in (("recuperacion", args.check_recovery, "/login/forgot_password.php"), ("alta", args.check_signup, "/login/signup.php")):
        if not enabled:
            continue
        if kind == "recuperacion":
            print("[!] Prueba de recuperacion: puede enviar correos para candidatos existentes.")
        for index, account in enumerate(probes):
            page = scoped_request(client, base, base + route + "?lang=en")
            if page is None or page.status_code != 200:
                break
            survey = HtmlSurvey(page.text)
            marker = "_qf__login_forgot_password_form" if kind == "recuperacion" else "_qf__login_signup_form"
            form = next((item for item in survey.forms if marker in item["fields"]), None)
            if not form:
                findings.append(Finding("INFO", "Prueba de " + kind + " no disponible", "No se encontro el formulario nativo esperado; puede estar deshabilitado o usar SSO."))
                break
            action = urljoin(page.url, form.get("action") or page.url)
            data = dict(form["fields"])
            data.update(username=account if "@" not in account else "", email=account if "@" in account else "")
            if kind == "recuperacion":
                data["submitbuttonemail" if "@" in account else "submitbuttonusername"] = "Search"
            if kind == "alta":
                # Validacion nativa con campos obligatorios vacios: no crea cuentas.
                data.update(password="", firstname="", lastname="", city="", country="", email2=data["email"])
                if not data["username"]:
                    data["username"] = "moodlereconmissing" + secrets.token_hex(12)
                data["submitbutton"] = "Create my new account"
            result = scoped_request(client, base, action, "POST", data)
            if result is None or result.status_code != 200:
                findings.append(Finding("INFO", "Prueba de " + kind + " incompleta", "Error de red o redireccion fuera del alcance."))
                break
            if kind == "recuperacion":
                state = recovery_state(result.text)
                if index == 0 and state == "NO_EXISTE":
                    findings.append(Finding("LOW", "Recuperacion revela inexistencia de cuenta",
                        "Un candidato aleatorio produjo un mensaje explicito de cuenta inexistente: revisar Protect usernames.",
                        reference="https://docs.moodle.org/en/Site_security_settings", confidence="OBSERVADO"))
                if index and state == "EXISTENCIA_INDICADA":
                    records.append({"username": account if "@" not in account else None, "email": account if "@" in account else None,
                        "source": route, "confidence": "EXISTENCIA_INDICADA (mensaje de recuperacion)"})
            else:
                errors = " ".join(item["text"] for item in HtmlSurvey(result.text).captures if item.get("id", "").startswith("id_error_"))
                state = "EXISTENCIA_INDICADA" if re.search(r"(?:username|email).*already (?:exists|registered)|usernametaken|email.*(?:ya existe|registrad)|(?:nombre de usuario|usuario).*ya existe", errors, re.I) else "INCONCLUSO"
                if index and state == "EXISTENCIA_INDICADA":
                    records.append({"username": account if "@" not in account else None, "email": account if "@" in account else None,
                        "source": route, "confidence": "EXISTENCIA_INDICADA (validacion de alta)"})
            if args.enum_delay:
                time.sleep(args.enum_delay)
    client.session.close()
    findings.append(Finding("INFO", "Pruebas de cuentas por formularios", f"{len(records)} candidato(s) con respuesta explicita de existencia. Respuestas genericas o distintas por si solas no se clasifican como cuentas validas.",
        evidence=" | ".join(str(item.get("username") or item.get("email")) for item in records), confidence="OBSERVADO" if records else "INCONCLUSO"))
    return records, findings


def enumerate_ws_users(args, base):
    if not args.ws_token_env:
        return [], None
    token = os.environ.get(args.ws_token_env)
    if not token:
        return [], Finding("INFO", "Consulta REST de usuarios no ejecutada", "La variable indicada no contiene un token.")
    client = new_audit_client(args)
    ids = list(range(args.user_id_start, args.user_id_end + 1))
    data = {"wstoken": token, "wsfunction": "core_user_get_users_by_field", "moodlewsrestformat": "json", "field": "id"}
    data.update({f"values[{i}]": value for i, value in enumerate(ids)})
    r = scoped_request(client, base, base.rstrip("/") + "/webservice/rest/server.php", "POST", data)
    records = []
    try:
        payload = r.json() if r is not None and r.status_code == 200 else None
        if isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict) and isinstance(item.get("id"), int):
                    records.append({"id": item["id"], "display_name": item.get("fullname") or " ".join((item.get("firstname", ""), item.get("lastname", ""))).strip(),
                        "username": item.get("username"), "emails": [item["email"]] if item.get("email") else [],
                        "sources": [base + "/webservice/rest/server.php"], "access_context": "token_autorizado", "confidence": "API_AUTORIZADA"})
    except (ValueError, AttributeError):
        pass
    client.session.close()
    return records, Finding("INFO", "Usuarios mediante API autorizada", f"{len(records)} registro(s) devuelto(s) para el intervalo de IDs; respeta permisos y funciones del token.",
        evidence="Token omitido de salida e informe. Un error REST no demuestra una fuga ni ausencia de usuarios.",
        reference="https://docs.moodle.org/en/Web_services", confidence="OBSERVADO" if records else "INCONCLUSO")



def ajax_call(client, base, method, arguments, sesskey=None):
    endpoint = base.rstrip("/") + ("/lib/ajax/service.php" if sesskey else "/lib/ajax/service-nologin.php")
    url = endpoint + ("?" + urlencode({"sesskey": sesskey}) if sesskey else "")
    old = client.session.headers.get("Content-Type")
    client.session.headers["Content-Type"] = "application/json"
    try:
        r = scoped_request(client, base, url, "POST", json.dumps([{"index": 0, "methodname": method, "args": arguments}]))
        data = r.json() if r is not None and r.status_code == 200 else None
        return data[0] if isinstance(data, list) and data and isinstance(data[0], dict) else None
    except (ValueError, AttributeError):
        return None
    finally:
        if old:
            client.session.headers["Content-Type"] = old
        else:
            client.session.headers.pop("Content-Type", None)


def enumerate_ajax_users(client, base, args):
    page = scoped_request(client, base, base.rstrip("/") + "/")
    if page is None:
        return [], Finding("INFO", "Consulta AJAX no disponible", "No se pudo obtener la pagina de la sesion.")
    match = re.search(r'["\']?sesskey["\']?\s*:\s*["\']([a-zA-Z0-9]+)["\']', page.text)
    if not match:
        return [], Finding("INFO", "Consulta AJAX no disponible", "No se encontro sesskey en la sesion proporcionada.")
    result = ajax_call(client, base, "core_user_get_users_by_field", {"field": "id", "values": list(range(args.user_id_start, args.user_id_end + 1))}, match[1])
    payload = result.get("data") if result and not result.get("error") else None
    records = []
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict) and isinstance(item.get("id"), int):
                records.append({"id": item["id"], "display_name": item.get("fullname") or " ".join((item.get("firstname", ""), item.get("lastname", ""))).strip(),
                    "username": item.get("username"), "emails": [item["email"]] if item.get("email") else [],
                    "sources": [base + "/lib/ajax/service.php"], "access_context": "cookies_proporcionadas", "confidence": "API_SESION (permisos no evaluados)"})
    return records, Finding("INFO", "Usuarios mediante AJAX con sesion proporcionada", f"{len(records)} registro(s) devuelto(s); no demuestra acceso indebido sin comparar las capacidades de la cuenta.",
        evidence="Funcion core_user_get_users_by_field; sesskey y cookies omitidos", confidence="OBSERVADO" if records else "INCONCLUSO")


def check_recovery_api(args, base):
    if not args.check_recovery_api:
        return [], []
    print("[!] Recuperacion por API: puede enviar correos para candidatos existentes.")
    client = new_audit_client(args)
    records, findings = [], []
    probes = ["moodlereconmissing" + secrets.token_hex(12)] + candidate_accounts(args)
    for index, account in enumerate(probes):
        arguments = {"username": account if "@" not in account else "", "email": account if "@" in account else ""}
        result = ajax_call(client, base, "core_auth_request_password_reset", arguments)
        if result is None:
            findings.append(Finding("INFO", "Recuperacion por API no disponible", "El endpoint no devolvio una respuesta reconocible."))
            break
        data = result.get("data", {})
        status = data.get("status", "") if isinstance(data, dict) else ""
        exception = result.get("exception", {})
        errorcode = exception.get("errorcode", "") if isinstance(exception, dict) else ""
        if index == 0 and (status == "emailpasswordconfirmnotsent" or errorcode in ("usernamenotfound", "emailnotfound")):
            findings.append(Finding("LOW", "API de recuperacion revela inexistencia de cuenta", "Comprobar Protect usernames; el candidato aleatorio recibio una respuesta explicita.", confidence="OBSERVADO"))
        if index and not result.get("error") and status in ("emailresetconfirmsent", "emailpasswordconfirmsent", "emailalreadysent", "emailpasswordconfirmnoemail"):
            records.append({"username": account if "@" not in account else None, "email": account if "@" in account else None,
                "source": "/lib/ajax/service-nologin.php", "confidence": "EXISTENCIA_INDICADA (API de recuperacion)"})
        if args.enum_delay:
            time.sleep(args.enum_delay)
    client.session.close()
    findings.append(Finding("INFO", "Candidatos por API de recuperacion", f"{len(records)} candidato(s) con indicacion explicita de existencia; la respuesta generica no confirma cuentas.", confidence="OBSERVADO" if records else "INCONCLUSO"))
    return records, findings


def check_eol(version):
    branch = ".".join((version or "").split(".")[:2])
    eol = load_meta().get("eol", BUILTIN_EOL).get(branch)
    if not eol:
        return None
    from datetime import date
    try:
        d = date.fromisoformat(eol)
        if d < date.today():
            return Finding("HIGH", f"Moodle {branch} fuera de soporte",
                           f"El soporte de seguridad de la rama {branch} termino "
                           f"el {eol}. No recibira nuevos parches.",
                           reference="https://endoflife.date/moodle",
                           confidence="CONFIRMADO")
        return Finding("INFO", f"Soporte de la rama {branch}",
                       f"Soporte de seguridad hasta {eol}.",
                       reference="https://endoflife.date/moodle")
    except ValueError:
        return None


# ----------------------------------------------------------------------
# Programa principal
# ----------------------------------------------------------------------
def scan(args):
    base = args.url.rstrip("/")
    client = HttpClient(timeout=args.timeout, proxy=args.proxy,
                        verify=not args.insecure, verbose=args.verbose)
    print(f"\n[*] Objetivo: {base}\n{'=' * 60}")

    print("[*] Fingerprinting de Moodle...")
    pages, evidence = fingerprint_moodle(client, base)
    if pages is None:
        sys.exit("[-] No hay conexion con el objetivo.")
    home, login_page = pages
    if not evidence:
        print("[-] No se encontraron evidencias de que sea Moodle. Continuo igualmente.")
    else:
        print(f"{GREEN}[+] Moodle detectado:{RESET}")
        for e in evidence:
            print(f"    - {e}")

    themes, inline_plugins = detect_themes_plugins_from_html(
        client, base, home.text or "")
    if themes:
        core = {"boost", "classic"}
        print(f"[+] Tema(s) activo(s): {', '.join(themes)}"
              + ("  (no-core: " + ", ".join(t for t in themes if t not in core) + ")"
                 if any(t not in core for t in themes) else ""))

    print("\n[*] Deteccion de version...")
    version, confidence, detail = detect_version(client, base, args.threads)
    if version:
        print(f"{GREEN}[+] Version de Moodle: {version} ({confidence}){RESET}")
    else:
        print("[-] No se pudo determinar la version.")
    print(f"    {detail}")

    if args.version:
        version, confidence, detail = args.version, "CONFIRMADA", "Version indicada por el auditor; no verificada remotamente"
        print("[+] Version indicada por el auditor: " + version)
    versions = [version] if version and confidence != "ESTIMADA (rama)" else list(getattr(client, "version_candidates", []))
    findings, user_records, account_records = [], [], []
    coverage_complete = None

    print("\n[*] Configuracion insegura y exposicion de informacion...")
    findings += check_exposure(client, base, {k.lower(): v for k, v in home.headers.items()})
    findings += check_misconfig(client, base)

    if not args.no_enum:
        print("[*] Enumeracion de plugins de terceros...")
        plugins = enumerate_plugins(client, base, args.threads)
        if inline_plugins:
            print(f"    Componentes en uso (HTML): "
                  f"{', '.join(f'{t}/{n}' for t, n in inline_plugins[:15])}")
        if plugins:
            print(f"{GREEN}[+] Plugins de terceros detectados:{RESET} "
                  + ", ".join(plugins))
            findings.append(Finding(
                "INFO", f"{len(plugins)} plugin(s) de terceros detectados",
                "Comprueba sus vulnerabilidades en https://moodle.org/plugins "
                "y bases GHSA/OSV. La presencia de un componente no demuestra una vulnerabilidad.",
                evidence=", ".join(plugins),
                reference="https://github.com/advisories?query=moodle",
                confidence="INDICIO (requiere verificacion)"))

    branches = sorted({".".join(v.split(".")[:2]) for v in versions or ([version] if version else [])})
    for branch in branches:
        eol = check_eol(branch)
        if eol:
            if confidence != "CONFIRMADA":
                eol.confidence = "POTENCIAL (rama inferida)"
            findings.append(eol)
    if args.scan:
        print("\n[*] Correlacion de vulnerabilidades conocidas...")
        if versions:
            vulns, coverage_complete = correlate_candidates(versions, client)
            for v in vulns:
                findings.append(Finding(v["severity"], v["id"], v["summary"],
                    evidence=v["evidence"], reference=v["reference"], confidence=v["confidence"]))
            if not coverage_complete:
                print("[!] Cobertura parcial: catalogo incorporado disponible; falta OSV o CSV completo. Ejecutar --update.")
            elif not vulns:
                print("[*] Sin coincidencias en las fuentes consultadas; no demuestra ausencia de vulnerabilidades.")
        else:
            print("[!] Sin candidatos de version exacta: usar --version X.Y.Z tras verificar en administracion.")

    guest_client = None
    if not args.no_guest_check:
        print("[*] Comprobacion de sesion invitada...")
        guest_client, finding = check_guest_login(args, base)
        findings.append(finding)
    if args.enum_users or (args.scan and not args.no_user_enum):
        print("[*] Enumeracion acotada de identidades publicas...")
        anonymous = new_audit_client(args)
        records, finding = enumerate_users(anonymous, base, args)
        anonymous.session.close()
        user_records.extend(records)
        findings.append(finding)
        if guest_client:
            records, finding = enumerate_users(guest_client, base, args, "invitado")
            user_records.extend(records)
            findings.append(finding)
        if args.cookies:
            authenticated = new_audit_client(args)
            jar = MozillaCookieJar(args.cookies)
            jar.load(ignore_discard=True, ignore_expires=False)
            authenticated.session.cookies.update(jar)
            records, finding = enumerate_users(authenticated, base, args, "cookies_proporcionadas")
            user_records.extend(records)
            findings.append(finding)
            records, finding = enumerate_ajax_users(authenticated, base, args)
            user_records.extend(records)
            findings.append(finding)
            authenticated.session.close()
    if guest_client:
        guest_client.session.close()
    account_records, extra_findings = check_account_forms(args, base)
    findings.extend(extra_findings)
    records, extra_findings = check_recovery_api(args, base)
    account_records.extend(records)
    findings.extend(extra_findings)
    records, finding = enumerate_ws_users(args, base)
    user_records.extend(records)
    if finding:
        findings.append(finding)

    if args.scan and not args.no_searchsploit:
        findings += searchsploit_findings(args)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            json.dump({"target": base, "version": version, "version_confidence": confidence,
                       "version_evidence": detail, "version_candidates": versions, "coverage_complete": coverage_complete,
                       "users": user_records, "account_candidates": account_records, "findings": [vars(x) for x in findings]}, f,
                      ensure_ascii=False, indent=2)
        print("[+] Informe JSON: " + args.report)

    # Informe final ordenado por severidad
    findings.sort(key=lambda f: (SEV_ORDER.get(f.severity, 9), f.confidence))
    print(f"\n{'=' * 60}\n[*] HALLAZGOS ({len(findings)})")
    if not findings:
        print("    Sin hallazgos.")
    for f in findings:
        f.show()
    print(f"\n[*] Fin del escaneo. Peticiones HTTP: N/A (con cache/reuse)\n")


def main():
    print(r"""
            .----------.
           /  .------.  \
          |   | >_   |   |-----[ AUDIT ]
           \  '------'  /
            '----..----'
                 ||
              ___||___
             /________\

              M O O D L E R E C O N
              developer rootmechanic
              Solo auditorias autorizadas
""")
    p = argparse.ArgumentParser(description="Scanner de seguridad para Moodle")
    p.add_argument("--url", help="URL base del Moodle objetivo")
    p.add_argument("--scan", action="store_true",
                   help="Correlacionar la version con vulnerabilidades conocidas")
    p.add_argument("--update", action="store_true",
                   help="Actualizar BD de hashes (GitHub) y advisories (moodle.org)")
    p.add_argument("--threads", type=int, default=8, help="Hilos (defecto 8)")
    p.add_argument("--timeout", type=int, default=10, help="Timeout HTTP en s (defecto 10)")
    p.add_argument("--proxy", help="Proxy, p.ej. http://127.0.0.1:8080")
    p.add_argument("-k", "--insecure", action="store_true",
                   help="Ignorar errores de certificado SSL")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--no-enum", action="store_true",
                   help="Omitir enumeracion de plugins de terceros")
    p.add_argument("--version", help="Version exacta verificada por el auditor (X.Y.Z)")
    p.add_argument("--exploitdb", help="Directorio local de Exploit-DB (files_exploits.csv)")
    p.add_argument("--no-searchsploit", action="store_true", help="Omitir consulta de Exploit-DB")
    p.add_argument("--report", help="Guardar informe JSON en este fichero")
    p.add_argument("--no-guest-check", action="store_true", help="Omitir prueba POST de acceso invitado")
    p.add_argument("--enum-users", action="store_true", help="Enumerar identidades visibles (tambien activo con --scan)")
    p.add_argument("--no-user-enum", action="store_true", help="Omitir recorrido de usuarios de --scan")
    p.add_argument("--user-id-start", type=int, default=1, help="Primer ID de perfil a consultar")
    p.add_argument("--user-id-end", type=int, default=20, help="Ultimo ID de perfil a consultar")
    p.add_argument("--enum-pages", type=int, default=40, help="Maximo de paginas por contexto de sesion")
    p.add_argument("--enum-delay", type=float, default=0.25, help="Pausa entre paginas/pruebas de cuentas")
    p.add_argument("--cookies", help="Cookies Netscape para enumeracion con sesion proporcionada")
    p.add_argument("--check-recovery", action="store_true", help="Probar Protect usernames; puede enviar correos")
    p.add_argument("--check-recovery-api", action="store_true", help="Probar recuperacion via AJAX sin login; puede enviar correos")
    p.add_argument("--check-learning-plans", action="store_true", help="Consultar planes por userid con las cookies proporcionadas")
    p.add_argument("--check-signup", action="store_true", help="Validar duplicados con campos requeridos vacios, sin crear cuentas")
    p.add_argument("--usernames", help="Fichero de usernames/emails candidatos para las pruebas de formularios")
    p.add_argument("--enum-candidates", type=int, default=20, help="Maximo de candidatos de formularios")
    p.add_argument("--ws-token-env", help="Variable de entorno con token autorizado para core_user_get_users_by_field")
    args = p.parse_args()
    if args.threads < 1 or args.timeout < 1:
        p.error("threads y timeout deben ser positivos")
    if args.user_id_start < 1 or args.user_id_end < args.user_id_start or args.enum_pages < 1 or args.enum_candidates < 1 or args.enum_delay < 0:
        p.error("Rangos y limites de enumeracion invalidos")
    if args.user_id_end - args.user_id_start > 999:
        p.error("Usar intervalos de hasta 1000 IDs")
    if args.check_learning_plans and not args.cookies:
        p.error("--check-learning-plans requiere --cookies de una sesion autorizada")
    if args.cookies and not (args.enum_users or (args.scan and not args.no_user_enum)):
        p.error("--cookies requiere enumeracion de usuarios activa")
    if args.usernames and not (args.check_recovery or args.check_recovery_api or args.check_signup):
        p.error("--usernames requiere una prueba de formularios/API de recuperacion")
    if args.enum_users and args.no_user_enum:
        p.error("--enum-users y --no-user-enum son incompatibles")
    if args.version and not re.fullmatch(r"\d+\.\d+\.\d+", args.version):
        p.error("--version requiere X.Y.Z estable")
    if args.url and (urlparse(args.url).scheme not in ("http", "https") or not urlparse(args.url).netloc):
        p.error("--url requiere URL HTTP(S) absoluta")
    if args.update:
        client = HttpClient(timeout=20, proxy=args.proxy,
                            verify=not args.insecure, verbose=args.verbose)
        ok = update_hash_db(client, args.threads)
        advisories_ok = update_vuln_db(client)
        sys.exit(0 if ok and advisories_ok else 1)
    if args.url:
        scan(args)
    else:
        p.print_help()


if __name__ == "__main__":
    main()
