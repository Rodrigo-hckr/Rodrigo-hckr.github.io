---
title: "PLATAFORMA - NombreMaquina"
date: YYYY-MM-DD HH:MM:00 +0000
categories: [CTF, Plataforma]
tags: [linux, privesc, web]
image:
  path: /assets/img/posts/nombremaquina/banner.png
  alt: NombreMaquina writeup banner
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
PLATAFORMA{...}
```

## ⬆️ Escalada de privilegios

Vector de escalada (SUID, sudo misconfig, cron, kernel exploit, etc.) y cómo lo explotaste.

```bash
# comando de escalada
```

**Flag de root:**
```
PLATAFORMA{...}
```

## 🛡️ Remediación

Recomendaciones concretas para corregir las vulnerabilidades encontradas.

## 🧠 Lecciones aprendidas

Qué aprendiste, qué herramienta nueva usaste, qué harías distinto la próxima vez.
