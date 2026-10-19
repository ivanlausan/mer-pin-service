# Servicio gratis de modelos MER (Cloudflare)

Esta variante usa Cloudflare Workers y D1, con un plan gratuito para uso personal. El servicio web y la página se publican juntos. El Worker usa D1 como base de datos persistente; no se necesita Render ni un servidor encendido.

## Pasos de configuración

1. Sube al repositorio de GitHub el contenido actualizado de esta carpeta: `worker.js`, `wrangler.toml`, `migrations/0001_init.sql` y `public/index.html`. Conserva también `server.js` si quieres mantener la versión anterior.
2. En Cloudflare, abre **Workers & Pages → D1 SQL Database → Create database**. Ponle `mer-pin-data`.
3. Copia el **Database ID** que Cloudflare muestra. Edita `wrangler.toml` en GitHub y reemplaza `REEMPLAZA_CON_EL_ID_DE_TU_BASE_DE_DATOS` por ese ID. Guarda el cambio.
4. En la base de datos D1, abre **Console** y ejecuta el SQL completo de `migrations/0001_init.sql`.
5. En Cloudflare, abre **Workers & Pages → Create → Workers Builds** (o importa el repositorio desde Workers & Pages) y selecciona el repositorio `mer-pin-service`. Indica que el directorio raíz contiene `wrangler.toml`; como comando de despliegue usa `npx wrangler deploy`.
6. En la configuración del Worker, abre **Settings → Variables and Secrets → Add**. Crea una variable de tipo **Secret** llamada `MER_PIN_SECRET` y pega una clave aleatoria de al menos 32 caracteres. Genérala en PowerShell con:

   ```powershell
   [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(48))
   ```

   Guarda la clave en un gestor de contraseñas. No la subas a GitHub ni la cambies después.
7. Espera a que el Worker se despliegue. Copia su URL HTTPS, por ejemplo `https://mer-pin-service.tu-cuenta.workers.dev`.

## Uso

En cada ordenador, instala/abre la aplicación de escritorio, configura esa misma URL y entra con el mismo PIN. Crea el PIN una vez y guarda los modelos con **Guardar en la nube**. El plan gratis incluye cuotas diarias; si se superan, las operaciones de base de datos pueden quedar temporalmente detenidas hasta que se restablezcan. Revisa las cuotas vigentes de Cloudflare antes de usarlo con muchos usuarios o modelos grandes.

Los modelos permanecen en D1 aunque el Worker se publique de nuevo. Conserva acceso a tu cuenta de Cloudflare y guarda la clave secreta de forma segura.
