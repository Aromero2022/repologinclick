# audit-login-tool

Herramienta de análisis del reporte **General Audit → User Login** de SAP SuccessFactors.

Recibe uno o varios CSV (o un .zip) exportados desde Scheduled Job Manager y genera un Excel (.xlsx) de una sola hoja con 21 columnas (A–U), incluyendo la fórmula `SI.CONJUNTO` para clasificar dispositivos.

## Instalación

Requiere Python 3.11 o superior.

```bash
pip install -r requirements.txt
```

## Uso

### Línea de comandos

```bash
# Un solo archivo
python audit_login.py septiembre_p1.csv -o auditoria.xlsx

# Varios archivos
python audit_login.py sept_p1.csv sept_p2.csv octubre.csv -o auditoria.xlsx

# Desde un .zip descargado de Scheduled Job Manager
python audit_login.py reporte_descargado.zip -o auditoria.xlsx

# Pasar una carpeta con CSVs y/o ZIPs
python audit_login.py ./descargas/ -o auditoria.xlsx
```

### Doble clic en Windows

Arrastra los archivos CSV o ZIP sobre `ejecutar_auditoria.bat`. El .bat invoca el script con todos los archivos recibidos.

## Opciones

| Opción | Descripción |
|---|---|
| `-o`, `--output` | Ruta del .xlsx de salida. Si se omite, se genera un nombre automático con el rango de fechas. |
| `--dedup` | Eliminar duplicados exactos por (Timestamp, Session ID, Action). Útil cuando las partes del reporte se enciman. |
| `--android-como-mobile` | Clasificar los User Agents `Linux; Android ...` como Mobile en vez de Laptop. |
| `--solo-logins` | Excluir logouts del resultado. |
| `--csv` | Exportar también un CSV UTF-8 además del .xlsx. |

## Estructura de salida

El archivo Excel tiene una sola hoja con autofiltro y panel inmovilizado, y estas columnas:

| Col | Encabezado | Origen |
|---|---|---|
| A | Operator ID | CSV |
| B | Operator Name | CSV |
| C | Proxy ID | CSV |
| D | Proxy Name | CSV |
| E | Secondary Login Operator ID | CSV |
| F | Secondary Login Operator Name | CSV |
| G | Audit Type | CSV |
| H | Timestamp | CSV (UTC ISO 8601) |
| I | Operation Completed? | CSV |
| J | Account ID | JSON (Audit Context) |
| K | Global User ID | JSON |
| L | Login Name | JSON |
| M | User Name | JSON |
| N | Assignment ID | JSON |
| O | IP Address | JSON |
| P | Login Channel | JSON |
| Q | Login Method | JSON |
| R | Login Device | JSON / User Agent |
| S | Session ID | JSON |
| T | Plataforma | Calculada desde User Agent |
| U | Tipo Dispositivo | Fórmula SI.CONJUNTO (IFS) |

## Resumen

Al terminar, la herramienta imprime y guarda un `.txt` con:

- Detalle por archivo (tamaño, registros, rango de fechas)
- Conteo por tipo de evento (Login, Logout, fallido)
- Conteo por plataforma y tipo de dispositivo
- Huecos de fechas mayores a 1 hora
- Advertencias (filas truncadas, plataformas inesperadas, duplicados)

## Tests

```bash
pytest tests/ -v
```

## Casos especiales que maneja

- **Última fila truncada:** la descarta y la reporta.
- **Archivos .zip:** extrae los CSV automáticamente.
- **Logouts:** se clasifican como MOBILE (sin IP ni dispositivo).
- **App móvil (TOKEN):** el Login Device es un JSON anidado → se reemplaza por MOBILE.
- **Logins fallidos:** se conservan; `Operation Completed?` = FALSE.
- **Partes que se enciman:** opción `--dedup` para eliminar duplicados.
- **Archivo abierto en Excel:** guarda con sufijo `_v2` si no puede sobrescribir.
- **Límite de Excel:** avisa si el resultado supera 1,048,575 filas.
