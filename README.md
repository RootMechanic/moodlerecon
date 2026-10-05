# MoodleRecon

Herramienta de reconocimiento y auditoría de seguridad para Moodle escrita en Python. Integra detección de versiones, correlación con avisos de seguridad, consulta de Exploit-DB y comprobaciones de exposición de información, usuarios visibles y acceso invitado.

> Utiliza la herramienta únicamente sobre sistemas para los que tengas autorización. Un hallazgo basado en la versión indica una posible vulnerabilidad; no demuestra que sea explotable.

## Funciones

- Identificación de versiones mediante hashes de archivos y otras evidencias públicas, conservando los candidatos cuando el resultado es ambiguo.
- Correlación de versiones con avisos oficiales de Moodle, OSV y un catálogo integrado de avisos relevantes.
- Severidad y evidencias por hallazgo, diferenciando coincidencias de versión de comprobaciones observadas.
- Detección de archivos expuestos, información de configuración y posibles problemas de cabeceras y cookies.
- Reconocimiento de plugins accesibles.
- Consulta de referencias de Exploit-DB mediante SearchSploit o un índice CSV local.
- Enumeración limitada de identidades publicadas en perfiles, páginas y feeds accesibles.
- Comprobación del inicio de sesión como invitado.
- Pruebas opcionales de formularios de registro y recuperación, y consultas con una sesión o token proporcionados por el auditor.
- Exportación de resultados a JSON.

## Instalación

Requiere Python 3 y el paquete `requests`. Clona el repositorio y abre una terminal en su directorio:

```bash
git clone https://github.com/RootMechanic/moodlerecon.git
cd moodlerecon
```

```bash
python -m venv .venv
```

Activa el entorno virtual en Linux:

```bash
source .venv/bin/activate
```

O en PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Instala las dependencias:

```bash
python -m pip install -r requirements.txt
```

El cálculo de CVSS 3.0 y 3.1 está integrado. Para procesar también vectores CVSS 4, instala el paquete opcional:

```bash
python -m pip install -r requirements-optional.txt
```

## Inicio rápido

Actualiza la base de hashes y los avisos oficiales:

```bash
python moodlerecon.py --update
```

La primera actualización puede tardar por la cantidad de versiones y archivos consultados. Los datos se guardan en `.moodlerecon/`; las consultas remotas necesitan acceso a Internet.

Ejecuta una auditoría con correlación de vulnerabilidades e informe JSON:

```bash
python moodlerecon.py --url https://moodle.example.com --scan --report informe.json
```

Consulta todas las opciones:

```bash
python moodlerecon.py --help
```

Sin `--scan`, se realizan comprobaciones de reconocimiento, exposición y acceso invitado. `--scan` añade la correlación con vulnerabilidades conocidas, la consulta de Exploit-DB y la enumeración de usuarios.

Para omitir la prueba de invitado y el recorrido de usuarios:

```bash
python moodlerecon.py --url https://moodle.example.com --scan --no-guest-check --no-user-enum
```

## Interpretación de resultados

La detección de versión distingue entre resultados confirmados, probables y ambiguos. Si existen varias versiones candidatas, la correlación indica si un aviso afecta a todas o solo a algunas. Los resultados dependen de las evidencias disponibles y de la cobertura de la base de hashes.

Si has verificado la versión por otra vía, puedes proporcionarla explícitamente:

```bash
python moodlerecon.py --url https://moodle.example.com --scan --version 3.11.7
```

`--version` es una declaración del auditor, no una verificación remota adicional.

Las condiciones de explotación pueden depender de permisos, módulos habilitados, configuración y parches aplicados sin cambiar la versión. El scanner no ejecuta exploits de SQL injection, lectura de archivos ni ejecución de código.

Por ejemplo, el aviso de **CVE-2024-43426** incluye versiones antiguas sin soporte: una versión 3.11.7 puede aparecer como potencialmente afectada. Hay que revisar el filtro TeX, la disponibilidad de pdfTeX y los parches instalados para determinar su aplicabilidad. La severidad del proveedor y una puntuación CVSS externa pueden usar escalas diferentes.

## SearchSploit y Exploit-DB

SearchSploit es opcional. En Kali Linux puedes instalarlo y actualizarlo con:

```bash
sudo apt update
sudo apt install exploitdb
searchsploit -u
```

Con `--scan`, MoodleRecon consulta referencias relacionadas con Moodle. No descarga ni ejecuta los exploits, y una coincidencia de producto no demuestra que el objetivo esté afectado.

También admite un directorio local que contenga `files_exploits.csv`, útil cuando SearchSploit no está disponible:

```bash
python moodlerecon.py --url https://moodle.example.com --scan --exploitdb /opt/exploitdb
```

En Windows:

```powershell
python moodlerecon.py --url https://moodle.example.com --scan --exploitdb C:\herramientas\exploitdb
```

La comprobación de actualización distingue estos casos:

- **Instalación gestionada por APT:** compara la versión instalada con la candidata de los repositorios configurados. El resultado depende de la caché local de APT; no ejecuta `apt update` automáticamente.
- **Índice independiente:** compara el índice local con el publicado. Un índice distinto no se considera automáticamente antiguo.
- **Comprobación no disponible:** informa de un estado desconocido, sin afirmar que esté desactualizado.

Si falta la herramienta o hay una actualización disponible, se muestran recomendaciones. Para omitir esta integración, usa `--no-searchsploit`.

Documentación: [SearchSploit](https://www.exploit-db.com/searchsploit).

## Usuarios y acceso invitado

La enumeración consulta perfiles y enlaces publicados en páginas accesibles, incluidos cursos, foros y feeds enlazados. Distingue nombres visibles, identificadores, nombres de usuario y correos cuando estos datos están realmente publicados. **Un nombre visible no equivale al nombre usado para iniciar sesión.**

Por defecto consulta los IDs del 1 al 20, con un límite de 40 páginas por contexto de sesión y una pausa de 0,25 segundos. Los intervalos de IDs tienen un máximo de 1000 por ejecución.

```bash
python moodlerecon.py --url https://moodle.example.com --enum-users --user-id-start 1 --user-id-end 50 --enum-pages 40 --enum-delay 0.5
```

La prueba de invitado usa una sesión independiente y comprueba que el estado de invitado persiste. Una cookie o una redirección por sí solas no confirman el acceso. Temas, idiomas o sistemas SSO no reconocidos pueden producir un resultado inconcluso. El acceso invitado puede ser una función intencionada y no implica acceso a todos los cursos.

### Sesión proporcionada por el auditor

Puedes usar un archivo de cookies en formato Netscape para consultar lo que permite una sesión autorizada. Debes exportarlo previamente desde esa sesión; el scanner no crea `cookies.txt`. Una ruta relativa se resuelve desde el directorio donde ejecutas el comando. El archivo se valida antes de iniciar las peticiones:

```bash
python moodlerecon.py --url https://moodle.example.com --enum-users --cookies cookies.txt
```

La comprobación opcional de planes de aprendizaje requiere estas cookies y enumeración activa:

```bash
python moodlerecon.py --url https://moodle.example.com --enum-users --cookies cookies.txt --check-learning-plans
```

Que un plan sea visible no demuestra por sí solo un fallo de autorización; hay que revisar las capacidades del usuario.

Para consultar `core_user_get_users_by_field` con un token autorizado, guarda el token en una variable de entorno y pasa su nombre:

```bash
python moodlerecon.py --url https://moodle.example.com --enum-users --ws-token-env MOODLE_WS_TOKEN
```

La consulta depende de los servicios y permisos asignados al token.

### Registro y recuperación: pruebas opcionales

Estas pruebas están desactivadas por defecto. Prepara un archivo `candidatos.txt` con un nombre de usuario o correo por línea; las líneas que empiezan por `#` se ignoran.

Comprobar errores explícitos de duplicado en el formulario de registro:

```bash
python moodlerecon.py --url https://moodle.example.com --check-signup --usernames candidatos.txt --enum-candidates 20
```

La prueba deja campos obligatorios vacíos para impedir la creación de cuentas. Formularios personalizados, CAPTCHA o SSO pueden impedir una conclusión.

Comprobar la recuperación mediante el formulario web o la API AJAX:

```bash
python moodlerecon.py --url https://moodle.example.com --check-recovery --usernames candidatos.txt
python moodlerecon.py --url https://moodle.example.com --check-recovery-api --usernames candidatos.txt
```

**Las pruebas de recuperación pueden enviar correos reales.** No completan cambios de contraseña. Las respuestas genéricas o diferencias de tiempo no se consideran prueba suficiente de que una cuenta exista.

## Opciones principales

| Opción | Uso |
| --- | --- |
| `--url URL` | URL base del Moodle, incluyendo su subdirectorio si lo tiene. |
| `--scan` | Correlación de CVE, Exploit-DB y enumeración de usuarios. |
| `--update` | Actualizar hashes y avisos oficiales; termina tras la actualización. |
| `--version X.Y.Z` | Versión exacta verificada por el auditor. |
| `--report ARCHIVO` | Guardar resultados en JSON. |
| `--threads N` | Hilos de trabajo; por defecto, 8. |
| `--timeout N` | Tiempo de espera HTTP en segundos; por defecto, 10. |
| `--proxy URL` | Proxy HTTP, por ejemplo `http://127.0.0.1:8080`. |
| `-k`, `--insecure` | Desactivar la verificación del certificado TLS. |
| `-v`, `--verbose` | Mostrar información adicional. |
| `--no-enum` | Omitir el reconocimiento de plugins. |
| `--no-searchsploit` | Omitir Exploit-DB. |
| `--exploitdb DIRECTORIO` | Usar un índice local de Exploit-DB. |
| `--no-guest-check` | Omitir la prueba de inicio de sesión invitado. |
| `--enum-users` | Activar enumeración de usuarios sin necesitar `--scan`. |
| `--no-user-enum` | Omitir la enumeración activada por `--scan`. |
| `--user-id-start N`, `--user-id-end N` | Intervalo de IDs que se consultarán. |
| `--enum-pages N` | Máximo de páginas por contexto; por defecto, 40. |
| `--enum-delay SEGUNDOS` | Pausa entre consultas de enumeración; por defecto, 0,25. |
| `--cookies ARCHIVO` | Cookies Netscape de una sesión proporcionada. |
| `--ws-token-env NOMBRE` | Variable de entorno con un token autorizado. |
| `--check-learning-plans` | Consultar planes usando las cookies proporcionadas. |
| `--check-signup` | Comprobar duplicados en el formulario de registro. |
| `--check-recovery` | Comprobar recuperación mediante el formulario web. |
| `--check-recovery-api` | Comprobar recuperación mediante AJAX. |
| `--usernames ARCHIVO` | Candidatos para las pruebas de registro o recuperación. |
| `--enum-candidates N` | Máximo de candidatos; por defecto, 20. |

## Informe JSON

El informe contiene el objetivo, la versión y sus evidencias, las versiones candidatas, la cobertura, los usuarios observados, los candidatos de cuenta y los hallazgos. Cada hallazgo incluye severidad, detalle, evidencia, referencia y confianza.

Los resultados pueden contener nombres o correos publicados por el sitio. Anonimiza los informes antes de compartirlos en GitHub y no publiques archivos de cookies ni tokens.

## Alcance y limitaciones

- La cobertura depende de los avisos disponibles, los datos locales y las respuestas del objetivo. No pretende sustituir a Nessus ni a una auditoría manual.
- No realiza una auditoría completa de PHP, Bootstrap, RequireJS u otras dependencias del servidor.
- Reconocer un plugin no identifica necesariamente su versión ni todas sus vulnerabilidades.
- La enumeración solo encuentra información accesible en los contextos consultados; no garantiza obtener todos los usuarios.
- La ausencia de hallazgos no demuestra ausencia de vulnerabilidades.
- Se realizan peticiones activas, incluida una prueba POST de acceso invitado por defecto. Ajusta los límites según el entorno.

## Verificacion

Se incluyen pruebas de regresion locales para rangos afectados, severidad CVSS, deteccion de invitado y proteccion de credenciales en redirecciones. No requieren un Moodle real:

```bash
python -B -m unittest discover -v
python -B moodlerecon.py --help
```

GitHub Actions ejecuta estas comprobaciones con Python 3.11 a 3.14. La matriz se verificara remotamente tras subir el repositorio; no equivale a una auditoria completa del scanner.

## Contribuciones

Consulta [CONTRIBUTING.md](CONTRIBUTING.md). Al comunicar un fallo, incluye el comando utilizado, la version de Python y la salida relevante, eliminando datos personales y secretos. Para posibles falsos positivos, aporta la version verificada y la evidencia que permita revisar el diagnostico.
