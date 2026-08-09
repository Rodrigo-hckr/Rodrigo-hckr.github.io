#!/usr/bin/env python3
"""
new_writeup.py — Generador de posts de writeup para blog Jekyll/Chirpy

Uso:
    python new_writeup.py "HTB - NombreMaquina"
    python new_writeup.py "WhoamI Labs - Identity" --categories CTF WhoamiLabs --tags linux web command-injection privesc
    python new_writeup.py "THM - Overpass" --open

Crea el archivo en _posts/YYYY-MM-DD-nombre-maquina.md con el front matter
de Chirpy ya listo y las secciones estándar del template.
"""

import argparse
import re
import sys
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuración por defecto — ajusta a tu gusto
# ---------------------------------------------------------------------------
POSTS_DIR = Path("_posts")
DEFAULT_CATEGORIES = ["CTF"]
DEFAULT_TAGS = ["linux"]

TEMPLATE = """---
title: "{title}"
date: {date} {time} +0000
categories: [{categories}]
tags: [{tags}]
---

## 📋 Resumen

Breve resumen de 2-3 líneas: qué tipo de vulnerabilidad tenía la máquina, dificultad, y el vector principal de compromiso.

| Campo | Valor |
|---|---|
| Plataforma | _ |
| Dificultad | _ |
| IP objetivo | _ |
| Vulnerabilidad principal | _ |

## 🔍 Reconocimiento

Resultados de nmap, enumeración inicial de puertos y servicios.

```bash
nmap -sV -sC -p- <IP> -oN recon.txt
```

```
# pegar output relevante aquí
```

## 🕸️ Enumeración

Fuzzing de directorios, análisis de la aplicación, hallazgos relevantes.

```bash
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt -x php,html,txt
```

## 💥 Explotación inicial (Foothold)

Cómo conseguiste ejecución de código / acceso inicial. Incluye el payload exacto y por qué funciona.

```bash
# payload / comando de explotación
```

**Flag de usuario:**
```
FLAG{{...}}
```

## ⬆️ Escalada de privilegios

Vector de escalada (SUID, sudo misconfig, cron, kernel exploit, etc.) y cómo lo explotaste.

```bash
# comando de escalada
```

**Flag de root:**
```
FLAG{{...}}
```

## 🛡️ Remediación

Recomendaciones concretas para corregir las vulnerabilidades encontradas.

## 🧠 Lecciones aprendidas

Qué aprendiste, qué herramienta nueva usaste, qué harías distinto la próxima vez.
"""


def slugify(text: str) -> str:
    """Convierte un título en un slug apto para nombre de archivo Jekyll."""
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)   # quita puntuación
    text = re.sub(r"[\s_]+", "-", text)     # espacios -> guiones
    text = re.sub(r"-+", "-", text)         # colapsa guiones repetidos
    return text.strip("-")


def build_post(title: str, categories: list[str], tags: list[str]) -> tuple[Path, str]:
    now = datetime.now()
    date_str = now.strftime("%Y-%m-%d")
    time_str = now.strftime("%H:%M:%S")
    slug = slugify(title)

    filename = f"{date_str}-{slug}.md"
    filepath = POSTS_DIR / filename

    content = TEMPLATE.format(
        title=title.replace('"', '\\"'),
        date=date_str,
        time=time_str,
        categories=", ".join(categories),
        tags=", ".join(tags),
    )
    return filepath, content


def main():
    parser = argparse.ArgumentParser(
        description="Crea un nuevo post de writeup en _posts/ con el formato Chirpy."
    )
    parser.add_argument("title", help='Título del writeup, ej. "HTB - NombreMaquina"')
    parser.add_argument(
        "--categories",
        nargs="+",
        default=DEFAULT_CATEGORIES,
        help=f"Categorías (default: {DEFAULT_CATEGORIES})",
    )
    parser.add_argument(
        "--tags",
        nargs="+",
        default=DEFAULT_TAGS,
        help=f"Tags (default: {DEFAULT_TAGS})",
    )
    parser.add_argument(
        "--posts-dir",
        default=None,
        help="Ruta a la carpeta _posts (default: ./_posts relativo al cwd)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Sobrescribe el archivo si ya existe",
    )

    args = parser.parse_args()

    global POSTS_DIR
    if args.posts_dir:
        POSTS_DIR = Path(args.posts_dir)

    if not POSTS_DIR.exists():
        print(f"[!] La carpeta {POSTS_DIR} no existe.")
        print("    Corre este script desde la raíz de tu repo Jekyll, o usa --posts-dir")
        sys.exit(1)

    filepath, content = build_post(args.title, args.categories, args.tags)

    if filepath.exists() and not args.force:
        print(f"[!] El archivo ya existe: {filepath}")
        print("    Usa --force para sobrescribirlo, o cambia el título.")
        sys.exit(1)

    filepath.write_text(content, encoding="utf-8")
    print(f"[+] Post creado: {filepath}")
    print(f"[+] Categorías:  {', '.join(args.categories)}")
    print(f"[+] Tags:        {', '.join(args.tags)}")
    print(f"[+] Edítalo y luego: git add {filepath} && git commit -m 'Add writeup: {args.title}'")


if __name__ == "__main__":
    main()
