#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cifrador.py - Herramienta de línea de comandos para cifrar y descifrar archivos
con AES-ECB, AES-GCM y ChaCha20-Poly1305 (y AES-CTR, solo con fines didácticos).

Subcomandos:
    generar-llave   Crea una llave aleatoria y la guarda en un archivo aparte.
    cifrar          Cifra un archivo con el modo elegido (--modo).
    descifrar       Descifra un archivo y avisa si fue manipulado.

Ejemplos:
    python3 cifrador.py generar-llave --modo gcm --bits 256 --llave mi.key
    python3 cifrador.py cifrar    --modo gcm --llave mi.key -i secreto.txt -o secreto.enc
    python3 cifrador.py descifrar            --llave mi.key -i secreto.enc -o recuperado.txt

Códigos de salida:
    0  todo bien
    1  error de uso (archivo no existe, llave inválida, etc.)
    2  ¡ARCHIVO MANIPULADO! (falló la verificación de autenticidad)

Formato del archivo cifrado (todo en bytes):
    +--------+---------+---------+---------------------+---------------------------+
    | "CIFR" | versión |  modo   | nonce (según modo)  | texto cifrado [+ etiqueta]|
    | 4 B    | 1 B     | 1 B     | 0, 12 o 16 B        | resto del archivo         |
    +--------+---------+---------+---------------------+---------------------------+
    En los modos autenticados (GCM y ChaCha20-Poly1305) los primeros 6 bytes
    (la cabecera) también quedan autenticados: si alguien los cambia, se detecta.
"""

import argparse
import os
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# --------------------------------------------------------------------------
# Constantes del formato de archivo
# --------------------------------------------------------------------------
MAGIC = b"CIFR"                 # "firma" para reconocer nuestros archivos
VERSION = 1                     # versión del formato
ID_MODO = {"ecb": 1, "gcm": 2, "chacha20": 3, "ctr": 4}
NOMBRE_MODO = {v: k for k, v in ID_MODO.items()}
DESCRIPCION = {
    "ecb": "AES-ECB (SIN autenticación, filtra patrones)",
    "gcm": "AES-GCM (cifra y autentica)",
    "chacha20": "ChaCha20-Poly1305 (cifra y autentica)",
    "ctr": "AES-CTR (SIN autenticación, solo didáctico)",
}
MODOS_AUTENTICADOS = ("gcm", "chacha20")
TAM_CABECERA = len(MAGIC) + 2   # magic + versión + modo = 6 bytes
TAM_NONCE_AEAD = 12             # GCM y ChaCha20-Poly1305 usan nonce de 12 bytes
TAM_NONCE_CTR = 16              # CTR usa un contador inicial de 16 bytes
TAM_ETIQUETA = 16               # etiqueta de autenticación (tag) de 16 bytes
TAMANOS_AES = (16, 24, 32)      # llaves AES-128, AES-192, AES-256 (en bytes)


# --------------------------------------------------------------------------
# Excepciones propias (para dar mensajes claros)
# --------------------------------------------------------------------------
class ErrorCifrador(Exception):
    """Error de uso o de formato (código de salida 1)."""


class ArchivoManipulado(ErrorCifrador):
    """La verificación de autenticidad falló (código de salida 2)."""


# --------------------------------------------------------------------------
# Manejo de llaves
# --------------------------------------------------------------------------
def tam_llave_bytes(modo: str, bits: int) -> int:
    """Devuelve cuántos bytes debe tener la llave para el modo pedido."""
    if modo == "chacha20":
        return 32  # ChaCha20 solo admite llaves de 256 bits
    if bits not in (128, 192, 256):
        raise ErrorCifrador("Para AES, --bits debe ser 128, 192 o 256.")
    return bits // 8


def generar_llave(modo: str, bits: int = 256) -> bytes:
    """Genera una llave aleatoria con el generador seguro del sistema operativo."""
    return os.urandom(tam_llave_bytes(modo, bits))


def guardar_llave(ruta: Path, llave: bytes, forzar: bool = False) -> None:
    """Guarda la llave en un archivo de texto (hexadecimal) con permisos 600."""
    if ruta.exists():
        if not forzar:
            raise ErrorCifrador(
                f"'{ruta}' ya existe. Usa --forzar si quieres reemplazarla "
                "(¡los archivos cifrados con la llave anterior quedarían ilegibles!)."
            )
        ruta.unlink()
    # O_EXCL evita carreras; 0o600 = solo el dueño puede leer/escribir.
    fd = os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(llave.hex() + "\n")


def cargar_llave(ruta: Path) -> bytes:
    """Lee una llave guardada con guardar_llave()."""
    if not ruta.is_file():
        raise ErrorCifrador(
            f"No encuentro el archivo de llave '{ruta}'. "
            "Créalo primero con el subcomando 'generar-llave'."
        )
    try:
        return bytes.fromhex(ruta.read_text().strip())
    except ValueError:
        raise ErrorCifrador(f"'{ruta}' no parece un archivo de llave válido (se esperaba hexadecimal).")


def validar_llave(modo: str, llave: bytes) -> None:
    """Comprueba que el tamaño de la llave sea el correcto para el modo."""
    if modo == "chacha20":
        if len(llave) != 32:
            raise ErrorCifrador(f"ChaCha20-Poly1305 necesita una llave de 32 bytes (256 bits); la tuya tiene {len(llave)}.")
    elif len(llave) not in TAMANOS_AES:
        raise ErrorCifrador(f"AES necesita una llave de 16, 24 o 32 bytes; la tuya tiene {len(llave)}.")


# --------------------------------------------------------------------------
# Cifrado y descifrado en memoria
# --------------------------------------------------------------------------
def _cabecera(modo: str) -> bytes:
    return MAGIC + bytes([VERSION, ID_MODO[modo]])


def cifrar_bytes(modo: str, llave: bytes, datos: bytes) -> bytes:
    """Cifra 'datos' y devuelve el contenido completo del archivo cifrado."""
    validar_llave(modo, llave)
    cab = _cabecera(modo)

    if modo == "ecb":
        # ECB trabaja por bloques de 16 bytes: hay que rellenar (PKCS7).
        relleno = padding.PKCS7(128).padder()
        relleno_datos = relleno.update(datos) + relleno.finalize()
        cifrador = Cipher(algorithms.AES(llave), modes.ECB()).encryptor()
        return cab + cifrador.update(relleno_datos) + cifrador.finalize()

    if modo == "ctr":
        nonce = os.urandom(TAM_NONCE_CTR)
        cifrador = Cipher(algorithms.AES(llave), modes.CTR(nonce)).encryptor()
        return cab + nonce + cifrador.update(datos) + cifrador.finalize()

    # Modos autenticados: el nonce NUNCA debe repetirse con la misma llave.
    nonce = os.urandom(TAM_NONCE_AEAD)
    aead = AESGCM(llave) if modo == "gcm" else ChaCha20Poly1305(llave)
    # 'cab' se pasa como datos asociados: queda autenticado (no cifrado).
    return cab + nonce + aead.encrypt(nonce, datos, cab)


def leer_cabecera(blob: bytes) -> str:
    """Valida la cabecera y devuelve el nombre del modo que declara el archivo."""
    if len(blob) < TAM_CABECERA or blob[:4] != MAGIC:
        raise ErrorCifrador("Este archivo no fue creado por cifrador.py (cabecera 'CIFR' ausente o dañada).")
    if blob[4] != VERSION:
        raise ErrorCifrador(f"Versión de formato desconocida: {blob[4]}.")
    if blob[5] not in NOMBRE_MODO:
        raise ErrorCifrador(f"Modo desconocido en la cabecera: {blob[5]}.")
    return NOMBRE_MODO[blob[5]]


def descifrar_bytes(llave: bytes, blob: bytes, modo_esperado: str = None):
    """
    Descifra el contenido de un archivo cifrado.
    Devuelve (datos, modo_detectado).
    Lanza ArchivoManipulado si un modo autenticado detecta alteraciones.
    """
    modo = leer_cabecera(blob)
    if modo_esperado and modo_esperado != modo:
        raise ErrorCifrador(
            f"Pediste --modo {modo_esperado} pero el archivo dice haber sido cifrado con '{modo}'."
        )
    validar_llave(modo, llave)
    cab, resto = blob[:TAM_CABECERA], blob[TAM_CABECERA:]

    if modo == "ecb":
        if len(resto) == 0 or len(resto) % 16 != 0:
            raise ErrorCifrador("Archivo ECB dañado: su tamaño no es múltiplo de 16 bytes.")
        descifrador = Cipher(algorithms.AES(llave), modes.ECB()).decryptor()
        con_relleno = descifrador.update(resto) + descifrador.finalize()
        try:
            quitar = padding.PKCS7(128).unpadder()
            return quitar.update(con_relleno) + quitar.finalize(), modo
        except ValueError:
            raise ErrorCifrador(
                "Relleno inválido: llave incorrecta o archivo dañado. "
                "(ECB no autentica, así que no puedo distinguir la causa.)"
            )

    if modo == "ctr":
        if len(resto) < TAM_NONCE_CTR:
            raise ErrorCifrador("Archivo CTR dañado: es más corto que su nonce.")
        nonce, cuerpo = resto[:TAM_NONCE_CTR], resto[TAM_NONCE_CTR:]
        descifrador = Cipher(algorithms.AES(llave), modes.CTR(nonce)).decryptor()
        return descifrador.update(cuerpo) + descifrador.finalize(), modo

    # GCM / ChaCha20-Poly1305
    if len(resto) < TAM_NONCE_AEAD + TAM_ETIQUETA:
        raise ArchivoManipulado("El archivo está truncado: falta el nonce o la etiqueta de autenticación.")
    nonce, cuerpo = resto[:TAM_NONCE_AEAD], resto[TAM_NONCE_AEAD:]
    aead = AESGCM(llave) if modo == "gcm" else ChaCha20Poly1305(llave)
    try:
        return aead.decrypt(nonce, cuerpo, cab), modo
    except InvalidTag:
        raise ArchivoManipulado(
            "Falló la verificación de autenticidad: el archivo fue MODIFICADO "
            "o la llave no es la correcta."
        )


# --------------------------------------------------------------------------
# Interfaz de línea de comandos
# --------------------------------------------------------------------------
def _normalizar_modo(texto: str) -> str:
    """Permite escribir 'chacha20-poly1305' además de 'chacha20'."""
    t = texto.lower().replace("_", "-")
    if t in ("chacha20", "chacha20-poly1305", "chacha"):
        return "chacha20"
    if t in ID_MODO:
        return t
    raise argparse.ArgumentTypeError(
        f"modo '{texto}' no válido. Opciones: ecb, gcm, chacha20 (o chacha20-poly1305), ctr."
    )


def _escribir_salida(ruta: Path, datos: bytes, forzar: bool) -> None:
    if ruta.exists() and not forzar:
        raise ErrorCifrador(f"'{ruta}' ya existe. Elige otro nombre con -o o usa --forzar para sobrescribir.")
    ruta.write_bytes(datos)


def _leer_entrada(ruta: Path) -> bytes:
    if not ruta.is_file():
        raise ErrorCifrador(f"No existe el archivo de entrada '{ruta}'.")
    return ruta.read_bytes()


def cmd_generar_llave(args) -> int:
    llave = generar_llave(args.modo, args.bits)
    guardar_llave(Path(args.llave), llave, args.forzar)
    print(f"[OK] Llave de {len(llave) * 8} bits guardada en '{args.llave}' (permisos 600).")
    print("     Guárdala APARTE de los archivos cifrados y no la subas a GitHub.")
    return 0


def cmd_cifrar(args) -> int:
    llave = cargar_llave(Path(args.llave))
    entrada = Path(args.entrada)
    salida = Path(args.salida) if args.salida else entrada.with_name(entrada.name + ".enc")
    datos = _leer_entrada(entrada)
    if args.modo not in MODOS_AUTENTICADOS:
        print(f"[AVISO] {DESCRIPCION[args.modo]}: no detectará si alguien modifica el archivo.", file=sys.stderr)
    _escribir_salida(salida, cifrar_bytes(args.modo, llave, datos), args.forzar)
    print(f"[OK] '{entrada}' cifrado con {DESCRIPCION[args.modo]} -> '{salida}'")
    return 0


def cmd_descifrar(args) -> int:
    llave = cargar_llave(Path(args.llave))
    entrada = Path(args.entrada)
    if args.salida:
        salida = Path(args.salida)
    elif entrada.suffix == ".enc":
        salida = entrada.with_suffix("")
    else:
        salida = entrada.with_name(entrada.name + ".dec")
    blob = _leer_entrada(entrada)
    try:
        datos, modo = descifrar_bytes(llave, blob, args.modo)
    except ArchivoManipulado as e:
        print("[ALERTA] ARCHIVO MANIPULADO O CORRUPTO", file=sys.stderr)
        print(f"         {e}", file=sys.stderr)
        print("         No se escribió ningún archivo de salida.", file=sys.stderr)
        return 2
    _escribir_salida(salida, datos, args.forzar)
    print(f"[OK] '{entrada}' descifrado con {DESCRIPCION[modo]} -> '{salida}'")
    if modo in MODOS_AUTENTICADOS:
        print("     Autenticidad verificada: el contenido no fue alterado.")
    else:
        print(f"[AVISO] {modo.upper()} NO autentica: no puedo garantizar que el contenido sea el original.", file=sys.stderr)
    return 0


def construir_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cifrador.py",
        description="Cifra y descifra archivos con AES-ECB, AES-GCM y ChaCha20-Poly1305.",
    )
    p.add_argument("--version", action="version", version="cifrador.py 1.0 (formato v%d)" % VERSION)
    sub = p.add_subparsers(dest="comando", required=True)

    g = sub.add_parser("generar-llave", help="crea una llave aleatoria en un archivo aparte")
    g.add_argument("--modo", "-m", type=_normalizar_modo, default="gcm", help="ecb | gcm | chacha20 | ctr (por defecto gcm)")
    g.add_argument("--bits", type=int, default=256, help="tamaño de llave AES: 128, 192 o 256 (por defecto 256; ChaCha20 siempre 256)")
    g.add_argument("--llave", "-k", default="llave.key", help="archivo donde guardar la llave (por defecto llave.key)")
    g.add_argument("--forzar", action="store_true", help="reemplaza el archivo de llave si ya existe")
    g.set_defaults(func=cmd_generar_llave)

    c = sub.add_parser("cifrar", help="cifra un archivo")
    c.add_argument("--modo", "-m", type=_normalizar_modo, required=True, help="ecb | gcm | chacha20 | ctr")
    c.add_argument("--llave", "-k", required=True, help="archivo de llave")
    c.add_argument("--entrada", "-i", required=True, help="archivo a cifrar")
    c.add_argument("--salida", "-o", help="archivo cifrado (por defecto <entrada>.enc)")
    c.add_argument("--forzar", action="store_true", help="sobrescribe la salida si ya existe")
    c.set_defaults(func=cmd_cifrar)

    d = sub.add_parser("descifrar", help="descifra un archivo y detecta manipulaciones")
    d.add_argument("--modo", "-m", type=_normalizar_modo, help="opcional: el modo se lee de la cabecera; si lo das, debe coincidir")
    d.add_argument("--llave", "-k", required=True, help="archivo de llave")
    d.add_argument("--entrada", "-i", required=True, help="archivo cifrado")
    d.add_argument("--salida", "-o", help="archivo descifrado (por defecto quita .enc o agrega .dec)")
    d.add_argument("--forzar", action="store_true", help="sobrescribe la salida si ya existe")
    d.set_defaults(func=cmd_descifrar)
    return p


def main(argv=None) -> int:
    args = construir_parser().parse_args(argv)
    try:
        return args.func(args)
    except ErrorCifrador as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
