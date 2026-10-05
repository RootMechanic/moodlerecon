# Contribuir

Antes de modificar el scanner, describe el problema y el comportamiento esperado. Para falsos positivos, incluye la version verificada, la referencia del aviso y evidencia anonimizada.

Instala las dependencias con `python -m pip install -r requirements.txt`. Comprueba la sintaxis y ejecuta `python -B moodlerecon.py --help`. Ejecuta `python -B -m unittest discover -v` e incorpora pruebas de regresion para cambios funcionales.

Prueba las comprobaciones de red en entornos locales o sistemas autorizados. No incluyas cookies, tokens, datos personales ni informes reales en commits o incidencias.

Documenta las nuevas opciones y distingue entre evidencia observada y vulnerabilidad inferida por version. Los cambios de correlacion y autenticacion deben incluir pruebas que cubran falsos positivos.
