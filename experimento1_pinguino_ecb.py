#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EXPERIMENTO 1 - El "pingüino ECB"

Idea: ciframos los PÍXELES de una imagen con colores planos (un logo) usando
AES-ECB y AES-GCM, y reconstruimos una imagen con los bytes cifrados.
  * ECB cifra cada bloque de 16 bytes por separado y SIN mezclar nada: bloques
    iguales de entrada dan bloques iguales de salida, así que la silueta del
    logo sigue siendo visible.
  * GCM mezcla un contador distinto en cada bloque: el resultado parece ruido.

Uso:
    python3 experimento1_pinguino_ecb.py                  # usa un logo generado
    python3 experimento1_pinguino_ecb.py --imagen mi.png  # usa tu propia imagen

Salida (carpeta resultados/exp1/): logo_original.png, logo_ecb.png,
logo_gcm.png y comparacion_ecb_gcm.png
"""

import argparse
import os
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # permite guardar gráficos sin pantalla (útil en una VM sin escritorio)
import matplotlib.pyplot as plt
from PIL import Image, ImageDraw
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CARPETA_SALIDA = Path("resultados/exp1")


def crear_logo(ruta: Path, lado: int = 256) -> None:
    """Dibuja un logo sencillo con pocos colores PLANOS (sin degradados)."""
    img = Image.new("RGB", (lado, lado), (255, 255, 255))           # fondo blanco
    d = ImageDraw.Draw(img)
    d.ellipse((20, 20, lado - 20, lado - 20), fill=(30, 90, 200))   # círculo azul
    d.rectangle((70, 70, 186, 186), fill=(240, 200, 30))            # cuadrado amarillo
    d.polygon([(128, 85), (172, 170), (84, 170)], fill=(200, 40, 40))  # triángulo rojo
    d.ellipse((108, 120, 148, 160), fill=(255, 255, 255))           # círculo blanco central
    img.save(ruta)


def cifrar_pixeles_ecb(pixeles: bytes, llave: bytes) -> bytes:
    """Cifra los bytes de los píxeles con AES-ECB (sin relleno: ajustamos el tamaño aparte)."""
    pendiente = (-len(pixeles)) % 16                   # bytes que faltan para llegar a múltiplo de 16
    datos = pixeles + b"\x00" * pendiente
    c = Cipher(algorithms.AES(llave), modes.ECB()).encryptor()
    return (c.update(datos) + c.finalize())[: len(pixeles)]   # recortamos al tamaño original


def cifrar_pixeles_gcm(pixeles: bytes, llave: bytes) -> bytes:
    """Cifra los bytes de los píxeles con AES-GCM y descarta la etiqueta (16 bytes finales)."""
    nonce = os.urandom(12)
    return AESGCM(llave).encrypt(nonce, pixeles, None)[:-16]


def main() -> None:
    ap = argparse.ArgumentParser(description="Experimento 1: pingüino ECB vs GCM")
    ap.add_argument("--imagen", help="imagen propia (idealmente con colores planos); si no, se genera un logo")
    args = ap.parse_args()

    CARPETA_SALIDA.mkdir(parents=True, exist_ok=True)
    ruta_original = CARPETA_SALIDA / "logo_original.png"
    if args.imagen:
        Image.open(args.imagen).convert("RGB").save(ruta_original)
    else:
        crear_logo(ruta_original)

    original = Image.open(ruta_original).convert("RGB")
    pixeles = original.tobytes()                 # bytes crudos: R,G,B,R,G,B,...
    llave = os.urandom(32)                       # llave AES-256 aleatoria, solo para este experimento

    img_ecb = Image.frombytes("RGB", original.size, cifrar_pixeles_ecb(pixeles, llave))
    img_gcm = Image.frombytes("RGB", original.size, cifrar_pixeles_gcm(pixeles, llave))
    img_ecb.save(CARPETA_SALIDA / "logo_ecb.png")
    img_gcm.save(CARPETA_SALIDA / "logo_gcm.png")

    # Imagen comparativa con tres paneles
    fig, ejes = plt.subplots(1, 3, figsize=(12, 4.4))
    for eje, imagen, titulo in zip(
        ejes,
        (original, img_ecb, img_gcm),
        ("Original", "Cifrada con AES-ECB\n(se ve la silueta)", "Cifrada con AES-GCM\n(parece ruido)"),
    ):
        eje.imshow(imagen)
        eje.set_title(titulo)
        eje.axis("off")
    fig.suptitle("Experimento 1: el 'pingüino ECB'", fontsize=14)
    fig.tight_layout(rect=[0, 0, 1, 0.93])  # deja espacio arriba para el título general
    fig.savefig(CARPETA_SALIDA / "comparacion_ecb_gcm.png", dpi=150)

    # Métrica sencilla: cuántos bloques de 16 bytes son únicos (ruido perfecto = casi todos)
    def bloques_unicos(b: bytes) -> str:
        bloques = [b[i:i + 16] for i in range(0, len(b) - 15, 16)]
        return f"{len(set(bloques))} únicos de {len(bloques)} bloques"

    print("Imágenes guardadas en", CARPETA_SALIDA.resolve())
    print("Bloques de 16 bytes en la imagen original :", bloques_unicos(pixeles))
    print("Bloques de 16 bytes cifrados con ECB      :", bloques_unicos(img_ecb.tobytes()))
    print("Bloques de 16 bytes cifrados con GCM      :", bloques_unicos(img_gcm.tobytes()))
    print("-> En ECB casi todos los bloques se repiten (hay patrón); en GCM casi todos son distintos.")


if __name__ == "__main__":
    main()
