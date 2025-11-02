# Lógica de Shamir reutilizada

# # ---------------------------
# IMPORTS
# ---------------------------
# importamos 'secrets' para generar aleatorios criptográficamente seguros
import secrets  # mejor que random para claves/aleatoriedad segura
# importamos 'base64' para codificar bytes a texto seguro (y volver)
import base64
# importamos 'math' para operaciones con tamaños (si hiciera falta)
import math

# ---------------------------
# PARÁMETRO: PRIMO (campo finito)
# ---------------------------
# Elegimos un primo grande para trabajar en un campo finito. 
# Esto evita colisiones y asegura que las operaciones modulares funcionen.
# Usamos un primo de 521 bits, enorme para cualquier texto base64
PRIME = 2**521 - 1  # Primo Mersenne usado en curvas elípticas (seguro y práctico)


# ---------------------------
# FUNCIÓN polynom: evaluar polinomio en un punto x
# ---------------------------
def polynom(x, coeffs):
    """
    Evalúa el polinomio definido por 'coeffs' en el punto x, usando módulo PRIME.
    - x: entero (x-coordinate)
    - coeffs: lista de coeficientes [a0, a1, a2, ...] (a0 = secreto)
    Devuelve: valor entero del polinomio en x (mod PRIME).
    """
    # iniciamos suma en 0
    total = 0
    # recorre cada coeficiente y suma coef * x^i (mod PRIME)
    for i in range(len(coeffs)):
        # pow(x, i, PRIME) calcula (x**i) % PRIME eficientemente
        term = (coeffs[i] * pow(x, i, PRIME)) % PRIME
        total = (total + term) % PRIME
    return total  # devolvemos el resultado modular

# ---------------------------
# FUNCIÓN split_secret: dividir secreto en n shares con umbral t
# ---------------------------
def split_secret(secret_int, n, t):
    """
    Divide 'secret_int' en 'n' fragmentos (shares), con umbral 't'.
    - secret_int: entero que representa el secreto (ej. int.from_bytes(...))
    - n: número total de shares a generar
    - t: umbral mínimo requerido para reconstruir
    Devuelve: lista de n tuples (x, y)
    """
    # comprobación simple: el secreto debe ser menor que el primo
    if secret_int >= PRIME:
        raise ValueError("El secreto es demasiado grande para el primo elegido.")
    # generamos coeficientes aleatorios seguros para el polinomio
    coeffs = [secret_int]  # coeficiente a0 = el secreto
    for _ in range(t - 1):
        # secrets.randbelow(PRIME) devuelve un entero en [0, PRIME-1]
        coeffs.append(secrets.randbelow(PRIME))
    # generamos los shares evaluando el polinomio en x=1..n
    shares = []
    for i in range(1, n + 1):
        y = polynom(i, coeffs)
        shares.append((i, y))
    return shares

# ---------------------------
# FUNCIÓN lagrange_interpolation: reconstruir usando Lagrange
# ---------------------------
def lagrange_interpolation(x, x_s, y_s):
    """
    Interpolación de Lagrange en el campo finito modulo PRIME.
    - x: punto donde queremos evaluar (usaremos 0 para recuperar a0 = secreto)
    - x_s: tupla/lista de x's de los shares
    - y_s: tupla/lista de y's de los shares
    Devuelve: valor entero interpolado en x (mod PRIME)
    """
    total = 0
    k = len(x_s)  # número de puntos
    # iteramos cada punto i
    for i in range(k):
        xi, yi = x_s[i], y_s[i]
        # empezamos con numerador/denominador para la base L_i(x)
        num = 1
        den = 1
        for j in range(k):
            if i == j:
                continue
            xj = x_s[j]
            # multiplicamos numerador por (x - xj) mod PRIME
            num = (num * (x - xj)) % PRIME
            # multiplicamos denominador por (xi - xj) mod PRIME
            den = (den * (xi - xj)) % PRIME
        # calculamos la inversa modular de den y multiplicamos por num
        inv_den = pow(den, -1, PRIME)  # inversa modular segura en Python 3.8+
        li = (num * inv_den) % PRIME
        # añadimos yi * li al total
        total = (total + (yi * li)) % PRIME
    return total

# ---------------------------
# FUNCIÓN recover_secret: wrapper para recuperar secreto desde shares
# ---------------------------
def recover_secret(shares, t):
    """
    Reconstruye el secreto usando los primeros 't' shares proporcionados.
    - shares: lista de tuples (x, y)
    - t: umbral
    Devuelve: entero que representa el secreto original
    """
    if len(shares) < t:
        raise ValueError("No hay suficientes shares para reconstruir el secreto.")
    # tomamos los primeros t shares (o podrías seleccionar cualesquiera t)
    selected = shares[:t]
    x_s = tuple([s[0] for s in selected])
    y_s = tuple([s[1] for s in selected])
    return lagrange_interpolation(0, x_s, y_s)

# ---------------------------
# HELPERS: convertir bytes <-> int y base64 seguro
# ---------------------------
def bytes_to_int(b: bytes) -> int:
    """Convierte bytes a entero (big endian)."""
    return int.from_bytes(b, "big")

def int_to_bytes(i: int) -> bytes:
    """Convierte entero a bytes con el tamaño mínimo necesario (big endian)."""
    if i == 0:
        return b"\x00"
    length = (i.bit_length() + 7) // 8
    return i.to_bytes(length, "big")

def b64encode_to_int(data_bytes: bytes) -> int:
    """
    Codifica bytes a Base64 (texto ASCII), luego convierte esa cadena Base64 a int.
    Esto asegura que el "secreto" sea texto seguro (sin problemas UTF-8).
    """
    b64 = base64.b64encode(data_bytes)  # bytes en Base64
    return bytes_to_int(b64)  # convertimos esos bytes Base64 a entero

def int_to_b64bytes_safely(i: int) -> bytes:
    """
    Convierte int de vuelta a bytes, y asegura que la cadena Base64 resultante 
    tenga padding correcto antes de decodificar.
    Devuelve bytes originales (después de base64-decoding).
    """
    # 1) convertir int a bytes
    b = int_to_bytes(i)
    # 2) intentar decodificar esos bytes como ASCII/Base64 string
    try:
        b64_str = b.decode("ascii")  # esto puede fallar si hay bytes no ascii (raro)
    except Exception:
        # si por alguna razón hay bytes no-ascii, limpiamos: ignoramos errores
        b64_str = b.decode("ascii", errors="ignore")
    # 3) reparar padding: Base64 usa bloques de 4 chars
    pad_needed = (-len(b64_str)) % 4  # número de '=' necesarios (0..3)
    if pad_needed:
        b64_str += "=" * pad_needed
    # 4) finalmente decodificamos base64 a bytes reales
    try:
        decoded = base64.b64decode(b64_str, validate=True)
    except Exception:
        # Si validate falla (datos corruptos), intentamos sin validate (más tolerante)
        decoded = base64.b64decode(b64_str + ("=" * pad_needed))
    return decoded