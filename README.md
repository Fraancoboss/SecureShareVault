Secure Communication System

Un sistema seguro de comunicación cliente-servidor que implementa AES-GCM para cifrado y Shamir Secret Sharing para la gestión de claves.
Características

    Cifrado de extremo a extremo usando AES-GCM

    Gestión segura de claves con Shamir Secret Sharing

    Comunicación via HTTP/JSON

    Resistente a ataques MITM (Man-in-the-Middle)

    Arquitectura modular y fácil de extender

Arquitectura
text

Cliente → [Cifrado AES] → [Dividir clave con Shamir] → Custodios seguros
                                                         ↓
                                                   (referencias)
                                                         ↓
Cliente → [Envía ciphertext + refs] → Servidor (almacenamiento)

Flujo de Comunicación:

    Cliente cifra el mensaje con AES-GCM

    Cliente divide la clave AES en 5 shares (umbral 3)

    Cada share viaja a un custodio distinto (canales seguros externos)

    El servidor solo recibe el ciphertext y referencias de custodia

    Recuperar la clave exige contactar con los custodios autorizados

Estructura del Proyecto
text

secure_communication_project/
├── client/                          # Aplicación Cliente + Servidor
│   ├── main.py                      # Servidor Flask principal
│   ├── send_secret.py               # Cliente que envía mensajes
│   └── config.py                    # Configuración URLs del cliente
│   └── templates/index.html         # Frontend básico de demostración
├── server/                          # Módulos de Cifrado
│   ├── config.py                    # Configuración centralizada
│   ├── aes_utils.py                 # Funciones AES-GCM
│   └── shamir_core.py               # Shamir Secret Sharing
├── client/share_vault.py            # Gestor de distribución de shares
├── tests/                           # Herramientas de Testing
│   └── mitm_improved.py             # MITM Proxy para pruebas
├── requirements.txt                 # Dependencias
├── clean_project.py                 # Script de limpieza
└── README.md                        # Este archivo

Configuración
Parámetros principales (server/config.py):
python

SERVER_HOST = "127.0.0.1"    # Host del servidor
SERVER_PORT = 5000           # Puerto del servidor
N_SHARES = 5                 # Total de shares a generar
THRESHOLD = 3                # Mínimo necesario para reconstruir
AES_KEY_SIZE = 32            # 256 bits para AES
NONCE_SIZE = 16              # Tamaño standard para GCM

Parámetros de distribución (client/config.py):
python

from pathlib import Path
SERVER_URL = "http://127.0.0.1:5000/api/relay"  # Endpoint del servidor
SHARE_CUSTODIANS = ["custodio_alpha", "custodio_bravo", "custodio_charlie"]
SECURE_SHARE_STORAGE_DIR = Path(__file__).resolve().parents[1] / "client_secure_shares"

Instalación y Uso
1. Instalar dependencias:
bash

pip install -r requirements.txt

2. Ejecutar el servidor:
bash

python client/main.py

3. Abrir la interfaz web (opcional):

   - Navega a http://127.0.0.1:5000/
   - Escribe un mensaje; el servidor lo procesa y devuelve **“Copia desde servidor: …”**
   - La vista muestra el ciphertext enviado, el mensaje cifrado de respuesta y las referencias de custodios generadas.

4. Enviar mensaje por CLI (opcional, segunda terminal):
bash

python client/send_secret.py

5. Probar seguridad con MITM:
bash

# Terminal 1: Servidor real (puerto 5000)
python client/main.py

# Terminal 2: MITM Proxy (puerto 5001)  
python tests/mitm_improved.py

# Terminal 3: Cliente conectado al MITM
# Modificar client/config.py: SERVER_URL = "http://127.0.0.1:5001/api/relay"
python client/send_secret.py

Testing
-------

Ejecutar pruebas locales:

```bash
pytest
```

Usar contenedores reproducibles:

```bash
# Levantar el servidor Flask
docker-compose up web

# Lanzar la suite de tests
docker-compose run --rm tests
```

Testing de Seguridad

El proyecto incluye un MITM Proxy para verificar que:

    Los mensajes viajan cifrados

    No hay fugas de información

    Shamir Secret Sharing funciona sin exponer suficientes shares a un único actor

    El atacante solo ve datos cifrados y metadatos limitados

Ejemplo de salida del MITM:
text

DATOS CIFRADOS DETECTADOS:
   • Ciphertext: 4teyEx+eeJT6BTsZ...
   • Nonce: 73fmtm9mx+OU98ulreuv2w==...
   • Tag: COFVnlGLqZKzaO0AkhWLeg==...
   • 5 shares generados, umbral: 3

Módulos Principales
server/aes_utils.py

    aes_encrypt(message, key) → (ciphertext, nonce, tag)

    aes_decrypt(ciphertext, key, nonce, tag) → plaintext

server/shamir_core.py

    split_secret(secret_int, n, t) → list of shares

    recover_secret(shares, t) → secret_int

client/share_vault.py

    SecureShareVault.distribute(shares) → referencias para custodios externos

tests/mitm_improved.py

    Proxy para interceptar y analizar tráfico

    Detección de datos cifrados vs texto plano

    Análisis de estructura de mensajes

Características de Seguridad
AES-GCM:

    Cifrado autenticado - Detecta modificaciones

    IV único por mensaje - Previene ataques de repetición

    Tags de autenticación - Verifica integridad

Shamir Secret Sharing:

    Umbral configurable - Mínimo de shares requeridos

    Seguridad información-teórica - Menos de T shares no revelan información

    Redundancia - Pueden perderse hasta N-T shares

Solución de Problemas
Error común: "MAC check failed"

    Verificar que aes_decrypt use el orden correcto: (ciphertext, key, nonce, tag)

    Confirmar que cliente y servidor usen la misma versión de los módulos

Limpiar archivos temporales:
bash

python clean_project.py

Resultados de Seguridad Verificados

    Comunicación completamente cifrada

    Shamir Secret Sharing funcional sin entregar suficientes shares al servidor

    Resistente a MITM - atacante solo ve datos cifrados y referencias opacas

    Autenticación e integridad con AES-GCM en el lado del cliente

    Gestión segura de claves mediante custodios externos

Próximas Mejoras

    Soporte para HTTPS

    Autenticación mutua

    Gestión de sesiones

    Interfaz gráfica de usuario

    Logs de auditoría de seguridad

Contribución

    Fork el proyecto

    Crea una rama para tu feature (git checkout -b feature/AmazingFeature)

    Commit tus cambios (git commit -m 'Add some AmazingFeature')

    Push a la rama (git push origin feature/AmazingFeature)

    Abre un Pull Request
