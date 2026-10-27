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

import argparse  # para leer opciones desde la línea de comandos (--imagen)
import os        # para generar bytes aleatorios con os.urandom
from pathlib import Path  # manejo cómodo de rutas de archivos y carpetas

import matplotlib
matplotlib.use("Agg")  # permite guardar gráficos sin pantalla (útil en una VM sin escritorio)
import matplotlib.pyplot as plt  # para armar la figura comparativa
from PIL import Image, ImageDraw  # Pillow: Image crea/abre/guarda imágenes, ImageDraw dibuja formas
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # piezas para armar AES-ECB
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # clase lista para cifrar con AES-GCM

# Carpeta donde se guardarán todos los resultados del experimento
CARPETA_SALIDA = Path("resultados/exp1")


def crear_logo(ruta: Path, lado: int = 256) -> None:
    """Dibuja un logo sencillo con pocos colores PLANOS (sin degradados)."""
    # Imagen cuadrada RGB de lado x lado píxeles, con fondo blanco
    img = Image.new("RGB", (lado, lado), (255, 255, 255))           # fondo blanco
    # "Pincel" para dibujar sobre la imagen
    d = ImageDraw.Draw(img)
    # Círculo grande que deja 20 px de margen en todos los lados
    d.ellipse((20, 20, lado - 20, lado - 20), fill=(30, 90, 200))   # círculo azul
    # Cuadrado centrado: esquina superior izquierda (70,70), inferior derecha (186,186)
    d.rectangle((70, 70, 186, 186), fill=(240, 200, 30))            # cuadrado amarillo
    # Triángulo definido por tres vértices (x, y)
    d.polygon([(128, 85), (172, 170), (84, 170)], fill=(200, 40, 40))  # triángulo rojo
    # Círculo pequeño en el centro del triángulo
    d.ellipse((108, 120, 148, 160), fill=(255, 255, 255))           # círculo blanco central
    # Guarda el logo en disco en la ruta indicada
    img.save(ruta)


def cifrar_pixeles_ecb(pixeles: bytes, llave: bytes) -> bytes:
    """Cifra los bytes de los píxeles con AES-ECB (sin relleno: ajustamos el tamaño aparte)."""
    # AES trabaja en bloques de 16 bytes: calculamos cuántos bytes faltan para completar el último
    pendiente = (-len(pixeles)) % 16                   # bytes que faltan para llegar a múltiplo de 16
    # Agregamos esos bytes en cero al final (si no falta ninguno, no se agrega nada)
    datos = pixeles + b"\x00" * pendiente
    # Creamos el cifrador AES (la llave define si es AES-128/192/256) en modo ECB
    c = Cipher(algorithms.AES(llave), modes.ECB()).encryptor()
    # Ciframos todo y recortamos el resultado al tamaño original para poder rearmar la imagen
    return (c.update(datos) + c.finalize())[: len(pixeles)]   # recortamos al tamaño original


def cifrar_pixeles_gcm(pixeles: bytes, llave: bytes) -> bytes:
    """Cifra los bytes de los píxeles con AES-GCM y descarta la etiqueta (16 bytes finales)."""
    # Nonce de 12 bytes aleatorios: GCM lo necesita y no debe repetirse con la misma llave
    nonce = os.urandom(12)
    # encrypt devuelve texto cifrado + etiqueta de autenticación (16 bytes al final);
    # el None indica que no hay datos asociados. [:-16] quita la etiqueta para igualar el largo
    return AESGCM(llave).encrypt(nonce, pixeles, None)[:-16]


def main() -> None:
    # --- Lectura de argumentos de la línea de comandos ---
    ap = argparse.ArgumentParser(description="Experimento 1: pingüino ECB vs GCM")
    # Opción --imagen: es opcional; si no se da, se genera el logo automáticamente
    ap.add_argument("--imagen", help="imagen propia (idealmente con colores planos); si no, se genera un logo")
    # Lee lo que el usuario escribió en la terminal
    args = ap.parse_args()

    # --- Preparación de carpeta y archivo original ---
    # Crea la carpeta de salida (y las padres); no da error si ya existe
    CARPETA_SALIDA.mkdir(parents=True, exist_ok=True)
    # Ruta donde se guardará la imagen original
    ruta_original = CARPETA_SALIDA / "logo_original.png"
    if args.imagen:
        # Imagen propia: se abre, se convierte a RGB (3 canales) y se guarda como original
        Image.open(args.imagen).convert("RGB").save(ruta_original)
    else:
        # Sin imagen propia: se dibuja el logo de ejemplo
        crear_logo(ruta_original)

    # Reabre la imagen guardada asegurando formato RGB
    original = Image.open(ruta_original).convert("RGB")
    pixeles = original.tobytes()                 # bytes crudos: R,G,B,R,G,B,...
    llave = os.urandom(32)                       # llave AES-256 aleatoria, solo para este experimento

    # --- Cifrado y reconstrucción de imágenes ---
    # Ciframos los bytes y los reinterpretamos como píxeles de una imagen del mismo tamaño
    img_ecb = Image.frombytes("RGB", original.size, cifrar_pixeles_ecb(pixeles, llave))
    img_gcm = Image.frombytes("RGB", original.size, cifrar_pixeles_gcm(pixeles, llave))
    # Guardamos ambas imágenes cifradas
    img_ecb.save(CARPETA_SALIDA / "logo_ecb.png")
    img_gcm.save(CARPETA_SALIDA / "logo_gcm.png")

    # Imagen comparativa con tres paneles
    # Figura con 1 fila y 3 columnas; figsize es el tamaño en pulgadas (ancho, alto)
    fig, ejes = plt.subplots(1, 3, figsize=(12, 4.4))
    # Recorremos a la vez cada panel, su imagen y su título
    for eje, imagen, titulo in zip(
        ejes,
        (original, img_ecb, img_gcm),
        ("Original", "Cifrada con AES-ECB\n(se ve la silueta)", "Cifrada con AES-GCM\n(parece ruido)"),
    ):
        eje.imshow(imagen)      # dibuja la imagen en el panel
        eje.set_title(titulo)   # pone el título del panel
        eje.axis("off")         # oculta los ejes numéricos
    # Título general de toda la figura
    fig.suptitle("Experimento 1: el 'pingüino ECB'", fontsize=14)
    fig.tight_layout(rect=[0, 0, 1, 0.93])  # deja espacio arriba para el título general
    # Guarda la figura comparativa con resolución de 150 puntos por pulgada
    fig.savefig(CARPETA_SALIDA / "comparacion_ecb_gcm.png", dpi=150)

    # Métrica sencilla: cuántos bloques de 16 bytes son únicos (ruido perfecto = casi todos)
    def bloques_unicos(b: bytes) -> str:
        # Corta los bytes en bloques completos de 16 (ignora un posible resto incompleto)
        bloques = [b[i:i + 16] for i in range(0, len(b) - 15, 16)]
        # set() elimina repetidos: su tamaño es la cantidad de bloques distintos
        return f"{len(set(bloques))} únicos de {len(bloques)} bloques"

    # --- Resultados por pantalla ---
    print("Imágenes guardadas en", CARPETA_SALIDA.resolve())
    print("Bloques de 16 bytes en la imagen original :", bloques_unicos(pixeles))
    print("Bloques de 16 bytes cifrados con ECB      :", bloques_unicos(img_ecb.tobytes()))
    print("Bloques de 16 bytes cifrados con GCM      :", bloques_unicos(img_gcm.tobytes()))
    print("-> En ECB casi todos los bloques se repiten (hay patrón); en GCM casi todos son distintos.")


# Ejecuta main() solo si el archivo se corre directamente (no si se importa desde otro script)
if __name__ == "__main__":
    main()