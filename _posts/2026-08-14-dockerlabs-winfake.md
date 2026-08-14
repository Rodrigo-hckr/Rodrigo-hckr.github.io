---
title: "DockerLabs WinFake"
date: 2026-08-14 14:41:47 +0000
categories: [CTF, DockerLabs]
tags: [ssh, bruteforce, python, fakeshell, backdoor, privilege-escalation]
---

## 📋 Resumen

Laboratorio de dificultad fácil de DockerLabs cuyo nombre ("WinFake") resume el concepto: un sitio web estático esconde un acróstico que revela un usuario SSH y, tras autenticar, el login cae en un intérprete de comandos falso escrito en Python que simula PowerShell/Windows sobre un sistema Linux real. Leyendo el código fuente del propio wrapper (accesible vía path traversal en su único comando de lectura de archivos) se descubre un backdoor intencional que invoca el `su` real del sistema, permitiendo escalar a root con la contraseña correcta.

| Campo | Valor |
|---|---|
| Plataforma | DockerLabs |
| Dificultad | Fácil |
| IP objetivo | 172.17.0.2 |
| Vulnerabilidad principal | Credenciales débiles (SSH) + Path Traversal en shell simulada + Backdoor de escalada |

---

## 🔍 Reconocimiento

```bash
nmap -sV -sC -p- 172.17.0.2 -oN recon_winfake.txt
```

![Recon nmap](/assets/img/posts/dockerlabs-winfake/01-recon-nmap.png)
_Solo dos puertos abiertos: 22/SSH (OpenSSH 9.6p1 Ubuntu) y 80/HTTP (Apache 2.4.58), con el sitio titulado "TechWorld Noticias"._

Al visitar el sitio web se encuentra un blog de noticias falso, aparentemente genérico:

![Sitio TechWorld Noticias](/assets/img/posts/dockerlabs-winfake/02-web-techworld-noticias.png)
_Página estática servida por Apache, sin backend visible a simple vista._

---

## 🕸️ Enumeración

Un fuzzing inicial de directorios no revela nada más allá de la página principal:

```bash
gobuster dir -u http://172.17.0.2/ -w /usr/share/wordlists/dirb/common.txt -x php,html -t 50
```

![Gobuster wordlist común](/assets/img/posts/dockerlabs-winfake/03-gobuster-common.png)
_Sin rutas adicionales — el sitio es completamente estático. Fuzzing posterior con wordlists más grandes (`directory-list-2.3-medium.txt`) confirmó lo mismo: no hay backend dinámico ni CMS._

Con el sitio agotado por fuerza bruta, se revisa el contenido de cada artículo con más detalle. Uno de ellos está oculto (`<article hidden="acrostico inicial">`), lo que sugiere revisar los títulos con atención:

```bash
curl -s http://172.17.0.2/ | grep -oP '(?<=<h2>)[^<]+'
```

![Acróstico en los títulos](/assets/img/posts/dockerlabs-winfake/04-acrostico-titulos.png)
_Tomando la primera letra de cada título (sin contar el artículo oculto "HIDDEN"), se forma el mensaje **"WINSERVER ROOT FAKENEWS"**._

Revisando también el código fuente completo del HTML, se encuentra una segunda pista más sutil en el CSS del `<body>`:

```css
body {
    ...
    top: pipe;
}
```

`top: pipe;` no es una propiedad CSS válida — es un Easter egg intencional que apunta al **nombre de usuario SSH: `pipe`**.

---

## 💥 Explotación inicial (Foothold)

Con el usuario `pipe` identificado, se lanza un ataque de diccionario contra SSH usando `rockyou.txt`:

```bash
hydra -l pipe -P /usr/share/wordlists/rockyou.txt ssh://172.17.0.2 -t 16 -f
```

![Hydra encuentra la contraseña](/assets/img/posts/dockerlabs-winfake/05-hydra-rockyou-pipe-kisses.png)
_Credenciales válidas: `pipe:kisses`._

Al conectar por SSH, el login no lleva a una shell de Linux normal, sino a un intérprete de comandos personalizado que simula PowerShell sobre Windows 10:

```
PS C:\Users\pipe>
```

Revisando `.bashrc` y `.profile` del usuario (accesibles antes de que el wrapper tome el control, o releídos después vía el propio wrapper) se confirma que ambos terminan invocando `/usr/local/bin/windows.py` — el script responsable de toda la simulación.

De los comandos "Windows" soportados por el wrapper, `type` (equivalente a `cat`) resulta ser el más útil: acepta rutas relativas sin sanitizar el `..`, permitiendo **path traversal** fuera del directorio home:

```powershell
type ../../../../etc/passwd
type user.txt
```

Con esa misma técnica se lee el código fuente del propio wrapper:

```powershell
type ../../../../usr/local/bin/windows.py
```

El script bloquea explícitamente su propia lectura mediante `windows.py` a secas, pero el path traversal con la ruta completa lo evade sin problema. Analizando el código se encuentra el punto crítico:

```python
# Ejecutar su root real
if cmd == "su" and args == ["root"]:
    try:
        subprocess.run(["su", "root"])
    except Exception as e:
        print(f"{RED}Error ejecutando su root: {e}{RESET}")
    continue
```

Es un **backdoor intencional**: si se escribe exactamente `su root`, el wrapper delega en el binario real de `su` del sistema operativo, heredando la terminal — una salida legítima de la shell simulada hacia el sistema real, siempre que se conozca la contraseña de `root`.

**Flag de usuario:**
```
d970977b69a543ce746095e2b660d107
```

---

## ⬆️ Escalada de privilegios

Con el backdoor identificado, solo falta la contraseña de `root`. Tras descartar varias combinaciones derivadas del acróstico (concatenado, con guiones, con distintas capitalizaciones), la contraseña correcta resulta ser el acróstico completo, con **cada palabra capitalizada y sin espacios**:

```powershell
su root
```

```
Password: WinServerRootFakeNews
```

![Backdoor su root](/assets/img/posts/dockerlabs-winfake/06-su-root-backdoor.png)
_El intento inicial contra `/var/log/apache2` (bloqueado, sin permisos) y varios intentos fallidos de `su root` antes de dar con la contraseña correcta, que finalmente devuelve una shell real de root (`root@<container-id>:/home/pipe#`)._

![Flag de root](/assets/img/posts/dockerlabs-winfake/07-root-flag.png)
_Confirmación de acceso total: `whoami` → `root`, `id` → `uid=0(root) gid=0(root) groups=0(root)`._

**Flag de root:**
```
fa209fcfb40c4276bd2ceb9f08bf5f7b
```

---

## 🛡️ Remediación

- **No reutilizar contraseñas del propio "lore" o pistas visibles del reto en entornos reales.** Aunque aquí es intencional por diseño del CTF, en un sistema productivo cualquier información expuesta en el frontend (comentarios, atributos HTML, CSS) nunca debe derivar en credenciales válidas.
- **Nunca implementar shells restringidas confiando en un wrapper de aplicación sin sandboxing real.** El script `windows.py` intenta simular una jaula, pero corre como el propio usuario del sistema sin ningún tipo de aislamiento (contenedor separado, `chroot`, `AppArmor`/`seccomp`), lo que permite que cualquier función de lectura de archivos (`type`) se convierta en una vía de path traversal completa.
- **Eliminar cualquier backdoor de "salida de emergencia" en shells restringidas.** El `if cmd == "su" and args == ["root"]` es exactamente el tipo de atajo que un desarrollador podría dejar "temporalmente" y terminar siendo el vector de compromiso total.
- **Sanitizar entradas de usuario que construyen rutas de archivo**, rechazando explícitamente secuencias `..` o normalizando (`os.path.realpath`) y verificando que el resultado siga dentro del directorio permitido antes de abrir cualquier archivo.
- **Forzar políticas de contraseñas robustas y MFA en SSH**, especialmente en cuentas con `ForceCommand`/shells restringidas, ya que suelen asumirse como "de bajo privilegio" y reciben menos escrutinio en la gestión de credenciales.

---

## 🧠 Lecciones aprendidas

WinFake es un buen ejercicio de **ingeniería social aplicada al reconocimiento**: buena parte del reto no está en explotar una vulnerabilidad técnica compleja, sino en prestar atención a detalles aparentemente decorativos (un acróstico en títulos de noticias, una propiedad CSS inválida a propósito) que en realidad son las pistas reales del vector de entrada. Una vez dentro, el patrón se repite: una "jaula" de aplicación (el wrapper de PowerShell falso) que parece restrictiva a primera vista, pero que termina teniendo tanto una fuga de información (path traversal en `type`, que permite leer su propio código fuente) como una puerta trasera explícita (`su root`) dejada por el propio diseño del reto. La lección técnica más transferible: cualquier "shell restringida" implementada a nivel de aplicación (no a nivel de sistema operativo) debe tratarse como potencialmente evadible, y el código fuente de esa restricción — si es alcanzable — es siempre el primer lugar donde buscar la salida.
