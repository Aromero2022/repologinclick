#!/usr/bin/env python3
"""
audit_login.py — Herramienta de análisis General Audit (User Login)

Procesa CSVs del reporte General Audit → User Login de SAP SuccessFactors
y genera un Excel (.xlsx) con columnas A–U, incluyendo la fórmula SI.CONJUNTO.
"""

import argparse
import io
import json
import os
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import xlsxwriter

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

CSV_COLUMNS = [
    "Operator ID",
    "Operator Name",
    "Proxy ID",
    "Proxy Name",
    "Secondary Login Operator ID",
    "Secondary Login Operator Name",
    "Audit Type",
    "Timestamp",
    "Operation Completed?",
    "Correlation ID",
    "Audit Context",
]

BASE_COLS = [
    "Operator ID",
    "Operator Name",
    "Proxy ID",
    "Proxy Name",
    "Secondary Login Operator ID",
    "Secondary Login Operator Name",
    "Audit Type",
    "Timestamp",
    "Operation Completed?",
]

JSON_KEYS = [
    "Account ID",
    "Global User ID",
    "Login Name",
    "User Name",
    "Assignment ID",
    "IP Address",
    "Login Channel",
    "Login Method",
    "Login Device",
    "Session ID",
]

NUMERIC_COLS = {"Login Name", "User Name", "Assignment ID"}

PLATFORM_MAP = {
    "windows": "Laptop",
    "linux": "Laptop",
    "iphone": "Mobile",
    "android": "Mobile",
    "ipad": "Tablet",
    "macintosh": "Laptop",
    "x11": "Laptop",
    "mobile": "Mobile",
}

VALID_PLATFORMS = {"Windows", "Linux", "X11", "Macintosh", "iPhone", "iPad", "Android", "MOBILE"}

OUTPUT_COLS = BASE_COLS + JSON_KEYS


# ---------------------------------------------------------------------------
# Funciones de parseo
# ---------------------------------------------------------------------------


def extract_platform(user_agent: str, android_as_mobile: bool = False) -> str:
    if not user_agent or user_agent.startswith("{"):
        return "MOBILE"
    m = re.search(r"\(([^;)]+)", user_agent)
    token = m.group(1).strip() if m else ""
    if not token:
        return "MOBILE"
    if token.startswith("Windows"):
        return "Windows"
    if token.startswith("Android"):
        return "Android"
    if android_as_mobile and token.startswith("Linux"):
        inner = user_agent[m.end() :]
        if "Android" in inner:
            return "Android"
    return token


def device_type(platform: str) -> str:
    return PLATFORM_MAP.get(platform.lower(), "")


def parse_audit_context(raw: str) -> dict:
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}


def read_csv_safe(filepath: str) -> tuple[pd.DataFrame, list[str]]:
    """Lee un CSV descartando la última fila si está truncada.

    Devuelve (DataFrame, lista_de_advertencias).
    """
    warnings = []
    with open(filepath, encoding="utf-8-sig") as f:
        txt = f.read()

    stripped = txt.rstrip("\r\n")
    lines_in_file = stripped.split("\n")
    has_data_rows = len(lines_in_file) > 1

    if stripped and has_data_rows and not stripped.endswith('}"'):
        last_nl = stripped.rfind("\n")
        if last_nl > 0:
            discarded_line = stripped[last_nl + 1 :]
            txt = stripped[: last_nl + 1]
            warnings.append(
                f"Fila truncada descartada en {os.path.basename(filepath)}: "
                f"«{discarded_line[:80]}…»"
            )
        else:
            warnings.append(
                f"Archivo {os.path.basename(filepath)} parece completamente truncado."
            )
            return pd.DataFrame(columns=CSV_COLUMNS), warnings

    df = pd.read_csv(io.StringIO(txt), dtype=str, keep_default_na=False)
    return df, warnings


def extract_csvs_from_zip(zip_path: str, dest_dir: str) -> list[str]:
    extracted = []
    with zipfile.ZipFile(zip_path, "r") as zf:
        for name in zf.namelist():
            if name.lower().endswith(".csv") and not name.startswith("__MACOSX"):
                zf.extract(name, dest_dir)
                extracted.append(os.path.join(dest_dir, name))
    return sorted(extracted)


def resolve_inputs(paths: list[str]) -> list[str]:
    """Resuelve la lista de entradas: expande .zip y carpetas."""
    csv_files = []
    for p in paths:
        if os.path.isdir(p):
            for f in sorted(os.listdir(p)):
                fp = os.path.join(p, f)
                if f.lower().endswith(".csv"):
                    csv_files.append(fp)
                elif f.lower().endswith(".zip"):
                    dest = os.path.join(p, "_extracted_" + Path(f).stem)
                    os.makedirs(dest, exist_ok=True)
                    csv_files.extend(extract_csvs_from_zip(fp, dest))
        elif p.lower().endswith(".zip"):
            dest = os.path.join(os.path.dirname(p) or ".", "_extracted_" + Path(p).stem)
            os.makedirs(dest, exist_ok=True)
            csv_files.extend(extract_csvs_from_zip(p, dest))
        elif p.lower().endswith(".csv"):
            csv_files.append(p)
        else:
            print(f"  Ignorando archivo no reconocido: {p}", file=sys.stderr)
    return csv_files


# ---------------------------------------------------------------------------
# Procesamiento principal
# ---------------------------------------------------------------------------


def process_files(
    csv_files: list[str],
    *,
    dedup: bool = False,
    android_as_mobile: bool = False,
    solo_logins: bool = False,
) -> tuple[pd.DataFrame, list[dict], list[str]]:
    """Procesa los CSV y devuelve (DataFrame final, info_por_archivo, advertencias)."""

    all_warnings: list[str] = []
    file_infos: list[dict] = []
    parts: list[pd.DataFrame] = []

    for filepath in csv_files:
        fsize = os.path.getsize(filepath)
        df_part, warnings = read_csv_safe(filepath)
        all_warnings.extend(warnings)

        n_records = len(df_part)
        fname = os.path.basename(filepath)

        ts_col = df_part["Timestamp"] if "Timestamp" in df_part.columns else pd.Series(dtype=str)
        ts_sorted = ts_col[ts_col != ""].sort_values()
        ts_min = ts_sorted.iloc[0] if len(ts_sorted) > 0 else ""
        ts_max = ts_sorted.iloc[-1] if len(ts_sorted) > 0 else ""

        file_infos.append(
            {
                "archivo": fname,
                "tamaño_mb": round(fsize / (1024 * 1024), 1),
                "registros": n_records,
                "primer_evento": ts_min,
                "ultimo_evento": ts_max,
            }
        )

        df_part["__src"] = fname
        parts.append(df_part)

    if not parts:
        return pd.DataFrame(), file_infos, all_warnings

    df = pd.concat(parts, ignore_index=True)

    # Parsear Audit Context
    ctx_parsed = df["Audit Context"].map(parse_audit_context)
    for key in JSON_KEYS:
        df[key] = ctx_parsed.map(lambda d, k=key: d.get(k, ""))
    df["Action"] = ctx_parsed.map(lambda d: d.get("Action", ""))

    # Plataforma (columna T)
    df["Plataforma"] = df["Login Device"].map(
        lambda ua: extract_platform(ua, android_as_mobile)
    )

    # Reemplazar Login Device vacío o JSON por MOBILE
    mask_mobile = (df["Login Device"] == "") | df["Login Device"].str.startswith("{", na=False)
    df.loc[mask_mobile, "Login Device"] = "MOBILE"

    # Tipo dispositivo (columna U, valor calculado)
    df["Tipo"] = df["Plataforma"].map(device_type)

    # Validar plataformas inesperadas
    unexpected = set(df["Plataforma"].unique()) - VALID_PLATFORMS
    if unexpected:
        all_warnings.append(f"Plataformas no esperadas encontradas: {unexpected}")

    # Filtrar solo logins
    if solo_logins:
        df = df[df["Action"] == "Login"].copy()

    # Deduplicar
    if dedup:
        before = len(df)
        df = df.drop_duplicates(subset=["Timestamp", "Session ID", "Action"], keep="first")
        removed = before - len(df)
        if removed > 0:
            all_warnings.append(f"Duplicados eliminados: {removed}")

    # Ordenar por Timestamp
    df = df.sort_values("Timestamp", kind="stable").reset_index(drop=True)

    return df, file_infos, all_warnings


# ---------------------------------------------------------------------------
# Generación de resumen
# ---------------------------------------------------------------------------


def generate_summary(
    df: pd.DataFrame,
    file_infos: list[dict],
    warnings: list[str],
    csv_files: list[str],
) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("  RESUMEN — Auditoría General Audit (User Login)")
    lines.append("=" * 70)
    lines.append("")

    # Info por archivo
    lines.append("ARCHIVOS PROCESADOS:")
    lines.append("-" * 70)
    total_lineas = 0
    for info in file_infos:
        lines.append(
            f"  {info['archivo']:40s}  {info['tamaño_mb']:>7.1f} MB  "
            f"{info['registros']:>10,} registros"
        )
        lines.append(
            f"    Rango: {info['primer_evento']}  →  {info['ultimo_evento']}"
        )
        total_lineas += info["registros"]
    lines.append(f"\n  Total registros válidos: {total_lineas:,}")
    lines.append(f"  Encabezados:             {len(csv_files)}")

    if warnings:
        lines.append(f"\n  Advertencias ({len(warnings)}):")
        for w in warnings:
            lines.append(f"    ⚠ {w}")

    if len(df) == 0:
        lines.append("\nNo hay datos para procesar.")
        return "\n".join(lines)

    lines.append("")

    # Por Action
    lines.append("POR TIPO DE EVENTO:")
    lines.append("-" * 40)
    action_counts = df["Action"].value_counts()
    for action, count in action_counts.items():
        label = action if action else "Login fallido (sin Action)"
        lines.append(f"  {label:35s} {count:>10,}")

    lines.append("")

    # Por plataforma
    lines.append("POR PLATAFORMA (columna T):")
    lines.append("-" * 40)
    plat_counts = df["Plataforma"].value_counts()
    for plat, count in plat_counts.items():
        lines.append(f"  {plat:35s} {count:>10,}")

    lines.append("")

    # Por tipo dispositivo
    lines.append("POR TIPO DE DISPOSITIVO (columna U):")
    lines.append("-" * 40)
    tipo_counts = df["Tipo"].value_counts()
    for tipo, count in tipo_counts.items():
        lines.append(f"  {tipo:35s} {count:>10,}")

    lines.append("")

    # Logouts que son MOBILE
    logouts_mobile = len(
        df[(df["Action"] == "Logout") & (df["Plataforma"] == "MOBILE")]
    )
    total_mobile = len(df[df["Plataforma"] == "MOBILE"])
    if total_mobile > 0:
        lines.append(
            f"Nota: De {total_mobile:,} registros MOBILE, "
            f"{logouts_mobile:,} son logouts ({logouts_mobile * 100 / total_mobile:.1f}%)."
        )

    # Huecos de fechas
    lines.append("")
    lines.append("HUECOS DE FECHAS (> 1 hora):")
    lines.append("-" * 40)
    try:
        ts = pd.to_datetime(df["Timestamp"], utc=True).sort_values().reset_index(drop=True)
        gaps = ts.diff()
        big_gaps = gaps[gaps > pd.Timedelta(hours=1)]
        if len(big_gaps) == 0:
            lines.append("  Ninguno detectado.")
        else:
            for idx in big_gaps.index:
                gap_h = big_gaps[idx].total_seconds() / 3600
                lines.append(
                    f"  {ts[idx - 1].isoformat()}  →  {ts[idx].isoformat()}  "
                    f"({gap_h:.1f} h)"
                )
    except Exception:
        lines.append("  No se pudieron analizar los timestamps.")

    lines.append("")
    lines.append("=" * 70)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Escritura del Excel
# ---------------------------------------------------------------------------

EXCEL_ROW_LIMIT = 1_048_575


def write_excel(
    df: pd.DataFrame,
    output_path: str,
    sheet_name: str = "General Audit",
) -> str:
    """Escribe el .xlsx y devuelve la ruta final usada."""

    if len(df) > EXCEL_ROW_LIMIT:
        raise ValueError(
            f"El resultado tiene {len(df):,} filas, que superan el límite de Excel "
            f"({EXCEL_ROW_LIMIT:,}). Usa --csv para exportar sin límite."
        )

    final_path = output_path
    if os.path.exists(output_path):
        try:
            with open(output_path, "a"):
                pass
        except (PermissionError, OSError):
            base, ext = os.path.splitext(output_path)
            final_path = f"{base}_v2{ext}"
            print(
                f"  ⚠ No se puede sobrescribir {output_path} (¿abierto en Excel?). "
                f"Guardando como {final_path}",
                file=sys.stderr,
            )

    wb = xlsxwriter.Workbook(
        final_path,
        {"strings_to_numbers": False, "strings_to_urls": False},
    )
    ws = wb.add_worksheet(sheet_name)
    bold = wb.add_format({"bold": True})

    # Encabezados
    headers = OUTPUT_COLS + ["Plataforma", "Tipo Dispositivo"]
    for j, h in enumerate(headers):
        ws.write_string(0, j, h, bold)

    # Datos
    data = df[OUTPUT_COLS + ["Plataforma", "Tipo"]].values.tolist()
    for i, row in enumerate(data, start=1):
        for j, col_name in enumerate(OUTPUT_COLS):
            v = row[j]
            if v == "" or v is None:
                continue
            if col_name in NUMERIC_COLS and isinstance(v, str) and v.isdigit():
                ws.write_number(i, j, int(v))
            else:
                ws.write_string(i, j, str(v))

        # Columna T (Plataforma) — índice 19
        plat_val = row[len(OUTPUT_COLS)]
        if plat_val:
            ws.write_string(i, 19, str(plat_val))

        # Columna U (Tipo Dispositivo) — fórmula IFS — índice 20
        cell_t = f"T{i + 1}"
        formula = (
            f'=_xlfn.IFS({cell_t}="Windows","Laptop",{cell_t}="Linux","Laptop",'
            f'{cell_t}="iPhone","Mobile",{cell_t}="Android","Mobile",{cell_t}="iPad","Tablet",'
            f'{cell_t}="Macintosh","Laptop",{cell_t}="X11","Laptop",{cell_t}="Mobile","Mobile")'
        )
        calc_val = row[len(OUTPUT_COLS) + 1]
        ws.write_formula(i, 20, formula, None, calc_val if calc_val else "")

    ws.autofilter(0, 0, len(df), 20)
    ws.freeze_panes(1, 0)
    wb.close()

    return final_path


# ---------------------------------------------------------------------------
# Nombre de archivo sugerido
# ---------------------------------------------------------------------------


def suggest_output_name(df: pd.DataFrame) -> str:
    try:
        ts = pd.to_datetime(df["Timestamp"], utc=True)
        ts_min = ts.min().strftime("%Y%m%d")
        ts_max = ts.max().strftime("%Y%m%d")
        return f"Auditoria_Login_{ts_min}_{ts_max}.xlsx"
    except Exception:
        return "Auditoria_Login.xlsx"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Procesa CSVs del reporte General Audit (User Login) de SAP SuccessFactors "
            "y genera un Excel con columnas A–U."
        ),
        epilog="Ejemplo: python audit_login.py sept_p1.csv sept_p2.csv oct.csv -o salida.xlsx",
    )
    parser.add_argument(
        "archivos",
        nargs="+",
        help="Archivos CSV, archivos .zip o carpetas con CSVs/ZIPs.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Ruta del .xlsx de salida. Si se omite, se genera un nombre automático.",
    )
    parser.add_argument(
        "--dedup",
        action="store_true",
        help="Eliminar duplicados exactos por (Timestamp, Session ID, Action).",
    )
    parser.add_argument(
        "--android-como-mobile",
        action="store_true",
        help="Clasificar User Agents Linux+Android como Mobile en vez de Laptop.",
    )
    parser.add_argument(
        "--solo-logins",
        action="store_true",
        help="Excluir logouts del resultado.",
    )
    parser.add_argument(
        "--csv",
        action="store_true",
        dest="export_csv",
        help="Exportar también un CSV UTF-8 además del .xlsx.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    print("Resolviendo archivos de entrada...")
    csv_files = resolve_inputs(args.archivos)

    if not csv_files:
        print("Error: no se encontraron archivos CSV.", file=sys.stderr)
        return 1

    print(f"Archivos CSV encontrados: {len(csv_files)}")
    for f in csv_files:
        size_mb = os.path.getsize(f) / (1024 * 1024)
        print(f"  {os.path.basename(f):40s} {size_mb:>7.1f} MB")

    print("\nProcesando...")
    df, file_infos, warnings = process_files(
        csv_files,
        dedup=args.dedup,
        android_as_mobile=args.android_como_mobile,
        solo_logins=args.solo_logins,
    )

    if len(df) == 0:
        print("No se encontraron registros válidos.", file=sys.stderr)
        return 1

    # Generar resumen
    summary = generate_summary(df, file_infos, warnings, csv_files)
    print(summary)

    # Determinar ruta de salida
    output_path = args.output or suggest_output_name(df)

    # Verificar límite de Excel
    if len(df) > EXCEL_ROW_LIMIT:
        print(
            f"\n⚠ El resultado tiene {len(df):,} filas y supera el límite de Excel "
            f"({EXCEL_ROW_LIMIT:,}). No se generará .xlsx.",
            file=sys.stderr,
        )
        if not args.export_csv:
            print("Usa --csv para exportar sin límite de filas.", file=sys.stderr)
            return 1
    else:
        # Nombre de hoja
        try:
            ts = pd.to_datetime(df["Timestamp"], utc=True)
            ts_min_str = ts.min().strftime("%d %b %Y")
            ts_max_str = ts.max().strftime("%d %b %Y")
            sheet = f"General Audit {ts_min_str}-{ts_max_str}"
            if len(sheet) > 31:
                sheet = "General Audit"
        except Exception:
            sheet = "General Audit"

        print(f"\nEscribiendo Excel: {output_path}")
        final = write_excel(df, output_path, sheet_name=sheet)
        print(f"  Guardado: {final} ({os.path.getsize(final) / (1024 * 1024):.1f} MB)")

    # CSV opcional
    if args.export_csv:
        csv_out = Path(output_path).with_suffix(".csv")
        export_cols = OUTPUT_COLS + ["Plataforma", "Tipo"]
        df[export_cols].to_csv(csv_out, index=False, encoding="utf-8-sig")
        print(f"  CSV exportado: {csv_out}")

    # Guardar resumen en .txt
    txt_path = Path(output_path).with_suffix(".txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(summary)
    print(f"  Resumen guardado: {txt_path}")

    print(f"\nTotal: {len(df):,} registros procesados.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
