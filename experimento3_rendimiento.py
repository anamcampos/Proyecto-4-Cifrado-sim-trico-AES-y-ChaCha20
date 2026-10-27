#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EXPERIMENTO 3 - Rendimiento: AES-128-GCM vs AES-256-GCM vs ChaCha20-Poly1305

Mide cuántos MB/s cifra cada algoritmo con la librería 'cryptography' (la misma
que usa cifrador.py) para varios tamaños de mensaje, y dibuja un gráfico de barras.
Opcionalmente repite la medición con 'openssl speed -evp ...' (--openssl).

Uso:
    python3 experimento3_rendimiento.py                 # medición rápida (~20 s)
    python3 experimento3_rendimiento.py --segundos 3    # más precisa
    python3 experimento3_rendimiento.py --openssl       # además, openssl speed

Salida (carpeta resultados/exp3/): rendimiento.csv, rendimiento.png
y, con --openssl, rendimiento_openssl.csv y rendimiento_openssl.png
"""

import argparse    # para leer opciones desde la línea de comandos (--segundos, --openssl)
import csv         # para escribir los resultados en archivos CSV
import os          # para generar bytes aleatorios con os.urandom
import platform    # para obtener información básica del procesador
import shutil      # para comprobar si 'openssl' existe en el PATH (shutil.which)
import statistics  # para calcular la mediana de las mediciones
import subprocess  # para ejecutar 'openssl speed' como comando externo
import time        # para medir tiempos con precisión (time.perf_counter)
from pathlib import Path  # manejo cómodo de rutas de archivos y carpetas

import matplotlib
matplotlib.use("Agg")  # guardar gráficos sin necesidad de pantalla
import matplotlib.pyplot as plt  # para dibujar los gráficos de barras
# Clases listas para cifrado autenticado (AEAD): AES-GCM y ChaCha20-Poly1305
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# Carpeta donde se guardarán todos los resultados del experimento
CARPETA = Path("resultados/exp3")
TAMANOS = [64, 1024, 8192, 65536, 1048576]            # bytes por mensaje
# Texto legible para mostrar cada tamaño en tablas y gráficos
ETIQUETA_TAM = {64: "64 B", 1024: "1 KiB", 8192: "8 KiB", 65536: "64 KiB", 1048576: "1 MiB"}
ALGORITMOS = {                                          # nombre -> función que crea el objeto cifrador
    "AES-128-GCM": lambda: AESGCM(os.urandom(16)),      # llave de 16 bytes = AES-128
    "AES-256-GCM": lambda: AESGCM(os.urandom(32)),      # llave de 32 bytes = AES-256
    "ChaCha20-Poly1305": lambda: ChaCha20Poly1305(os.urandom(32)),  # ChaCha20 siempre usa llave de 32 bytes
}
# Color de las barras de cada algoritmo en los gráficos
COLORES = {"AES-128-GCM": "#2b7bba", "AES-256-GCM": "#1b4f7c", "ChaCha20-Poly1305": "#e08a1e"}


def info_cpu() -> tuple:
    """Devuelve (modelo de CPU, ¿tiene AES-NI?). Equivale a: grep -o aes /proc/cpuinfo | head -1"""
    # Valores por defecto: nombre genérico del procesador y AES-NI desconocido (None)
    modelo, aes_ni = platform.processor() or platform.machine(), None
    try:
        # En Linux, /proc/cpuinfo describe la CPU
        texto = Path("/proc/cpuinfo").read_text()
        for linea in texto.splitlines():
            if linea.startswith("model name"):
                # Toma lo que está después de los ":" como nombre del modelo
                modelo = linea.split(":", 1)[1].strip()
                break
        # Busca la línea de flags (en ARM se llama "Features") con las capacidades de la CPU
        flags = next((l for l in texto.splitlines() if l.startswith(("flags", "Features"))), "")
        aes_ni = "aes" in flags.split(":", 1)[-1].split()   # buscamos la palabra exacta "aes" entre los flags
    except OSError:
        pass  # no es Linux: dejamos aes_ni en None (desconocido)
    return modelo, aes_ni


def medir(cifrador, tam: int, segundos: float) -> float:
    """Cifra mensajes de 'tam' bytes durante ~'segundos' y devuelve MB/s (mediana de 3 rondas)."""
    # Mensaje aleatorio del tamaño a probar (se reutiliza en todas las iteraciones)
    mensaje = os.urandom(tam)
    contador = 0   # se usará para fabricar un nonce distinto en cada cifrado
    rondas = []    # aquí se guarda la velocidad de cada una de las 3 rondas
    for _ in range(3):
        # Reinicia el conteo de bytes y toma la hora de inicio de la ronda
        bytes_cifrados, inicio = 0, time.perf_counter()
        # Cada ronda dura un tercio del tiempo total pedido
        limite = inicio + segundos / 3
        while time.perf_counter() < limite:
            # Nonce distinto en cada mensaje (como exige la seguridad): un contador de 12 bytes.
            contador += 1
            # Cifra el mensaje (None = sin datos asociados); el resultado no se usa, solo importa el tiempo
            cifrador.encrypt(contador.to_bytes(12, "big"), mensaje, None)
            bytes_cifrados += tam
        # Velocidad de la ronda: bytes / segundos transcurridos / 1 millón = MB/s
        rondas.append(bytes_cifrados / (time.perf_counter() - inicio) / 1e6)
    # La mediana evita que una ronda anómala distorsione el resultado
    return statistics.median(rondas)


def grafico_python(resultados: dict, ruta: Path, subtitulo: str) -> None:
    """Barras agrupadas: eje X = tamaño del mensaje, una barra por algoritmo."""
    ancho = 0.26  # ancho de cada barra
    fig, eje = plt.subplots(figsize=(10, 5.5))
    for i, (alg, valores) in enumerate(resultados.items()):
        # Desplaza cada algoritmo a izquierda/centro/derecha dentro de cada grupo de barras
        posiciones = [j + (i - 1) * ancho for j in range(len(TAMANOS))]
        barras = eje.bar(posiciones, [valores[t] for t in TAMANOS], ancho, label=alg, color=COLORES[alg])
        # Escribe el valor numérico encima de cada barra
        eje.bar_label(barras, fmt="%.0f", fontsize=7, padding=2)
    # Una marca en el eje X por cada tamaño, con su etiqueta legible
    eje.set_xticks(range(len(TAMANOS)))
    eje.set_xticklabels([ETIQUETA_TAM[t] for t in TAMANOS])
    eje.set_xlabel("Tamaño de cada mensaje cifrado")
    eje.set_ylabel("Velocidad (MB/s) - más alto es mejor")
    eje.set_title("Rendimiento de cifrado autenticado (librería 'cryptography')\n" + subtitulo, fontsize=11)
    eje.legend()                    # leyenda con el color de cada algoritmo
    eje.grid(axis="y", alpha=0.3)   # líneas horizontales suaves de referencia
    fig.tight_layout()
    fig.savefig(ruta, dpi=150)      # guarda el gráfico como imagen
    plt.close(fig)                  # libera la memoria de la figura


def correr_openssl(segundos: int) -> dict:
    """Ejecuta 'openssl speed -evp ...' y devuelve {algoritmo: {tamaño: MB/s}}."""
    # Si openssl no está instalado, se avisa y se devuelve un diccionario vacío
    if shutil.which("openssl") is None:
        print("[AVISO] No encontré 'openssl' en el PATH; me salto esta parte.")
        return {}
    # Nombre bonito -> nombre que entiende openssl
    nombres = {"AES-128-GCM": "aes-128-gcm", "AES-256-GCM": "aes-256-gcm", "ChaCha20-Poly1305": "chacha20-poly1305"}
    salida = {}
    for bonito, evp in nombres.items():
        print(f"  openssl speed -evp {evp} ...")
        # -elapsed mide tiempo real y -seconds fija la duración de cada prueba
        r = subprocess.run(["openssl", "speed", "-elapsed", "-seconds", str(segundos), "-evp", evp],
                           capture_output=True, text=True)
        encabezado, fila = None, None
        for linea in r.stdout.splitlines():
            if linea.startswith("type"):
                # Línea de encabezado: extrae los tamaños de bloque (16, 64, 256...)
                encabezado = [int(x) for x in linea.replace("bytes", " ").split()[1:]]
            elif linea.lower().startswith(evp.lower()) and encabezado:
                # Línea de datos: quita la "k" final de cada valor y pasa de kB/s a MB/s
                fila = [float(x.rstrip("k")) / 1000 for x in linea.split()[1:]]   # kB/s -> MB/s
        if encabezado and fila:
            # Empareja cada tamaño con su velocidad
            salida[bonito] = dict(zip(encabezado, fila))
    return salida


def grafico_openssl(res: dict, ruta: Path, subtitulo: str) -> None:
    # Toma los tamaños de bloque del primer algoritmo y los ordena
    tams = sorted(next(iter(res.values())))
    ancho = 0.26  # ancho de cada barra
    fig, eje = plt.subplots(figsize=(10, 5.5))
    for i, (alg, valores) in enumerate(res.items()):
        # Desplaza cada algoritmo dentro de su grupo de barras
        pos = [j + (i - 1) * ancho for j in range(len(tams))]
        barras = eje.bar(pos, [valores[t] for t in tams], ancho, label=alg, color=COLORES[alg])
        # Valor numérico encima de cada barra
        eje.bar_label(barras, fmt="%.0f", fontsize=7, padding=2)
    eje.set_xticks(range(len(tams)))
    eje.set_xticklabels([f"{t} B" for t in tams])
    eje.set_xlabel("Tamaño de bloque (bytes)")
    eje.set_ylabel("Velocidad (MB/s) - más alto es mejor")
    eje.set_title("Rendimiento según 'openssl speed -evp'\n" + subtitulo, fontsize=11)
    eje.legend()
    eje.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(ruta, dpi=150)
    plt.close(fig)


def main() -> None:
    # --- Lectura de argumentos de la línea de comandos ---
    ap = argparse.ArgumentParser(description="Experimento 3: rendimiento AES-GCM vs ChaCha20-Poly1305")
    # --segundos: duración de cada medición (acepta decimales)
    ap.add_argument("--segundos", type=float, default=1.0, help="segundos de medición por cada combinación (por defecto 1)")
    # --openssl: es un interruptor (no recibe valor); si está presente vale True
    ap.add_argument("--openssl", action="store_true", help="repite la medición con 'openssl speed'")
    args = ap.parse_args()

    # Crea la carpeta de resultados si no existe
    CARPETA.mkdir(parents=True, exist_ok=True)
    # Obtiene el modelo de CPU y si soporta AES-NI, y lo muestra en pantalla
    modelo, aes_ni = info_cpu()
    texto_aesni = {True: "SI", False: "NO", None: "desconocido"}[aes_ni]
    print(f"CPU: {modelo}")
    print(f"¿AES-NI disponible?: {texto_aesni}   (equivale a: grep -o aes /proc/cpuinfo | head -1)")
    print(f"Midiendo {len(ALGORITMOS)} algoritmos x {len(TAMANOS)} tamaños, ~{args.segundos}s cada uno...\n")

    # --- Mediciones con la librería 'cryptography' ---
    resultados = {}   # estructura: {algoritmo: {tamaño: MB/s}}
    for nombre, crear in ALGORITMOS.items():
        cifrador = crear()   # crea el cifrador con una llave aleatoria nueva
        resultados[nombre] = {}
        for tam in TAMANOS:
            # Mide la velocidad y la imprime enseguida con formato alineado
            resultados[nombre][tam] = medir(cifrador, tam, args.segundos)
            print(f"  {nombre:<18} {ETIQUETA_TAM[tam]:>7}: {resultados[nombre][tam]:>9.1f} MB/s")

    # --- Guardado en CSV: una fila por algoritmo, una columna por tamaño ---
    with open(CARPETA / "rendimiento.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["algoritmo"] + [f"{t}_bytes_MBps" for t in TAMANOS])   # encabezado
        for nombre, vals in resultados.items():
            w.writerow([nombre] + [f"{vals[t]:.1f}" for t in TAMANOS])

    # Subtítulo del gráfico con el modelo de CPU y el dato de AES-NI
    subt = f"CPU: {modelo} | AES-NI: {texto_aesni}"
    grafico_python(resultados, CARPETA / "rendimiento.png", subt)
    print(f"\nGuardado: {CARPETA / 'rendimiento.png'} y {CARPETA / 'rendimiento.csv'}")

    # --- Parte opcional: repetir la medición con openssl ---
    if args.openssl:
        print("\nMidiendo con openssl speed...")
        # openssl solo acepta segundos enteros, y al menos 1
        res = correr_openssl(max(1, round(args.segundos)))
        if res:   # solo si openssl existe y devolvió datos
            tams = sorted(next(iter(res.values())))
            # CSV con los resultados de openssl
            with open(CARPETA / "rendimiento_openssl.csv", "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["algoritmo"] + [f"{t}_bytes_MBps" for t in tams])
                for nombre, vals in res.items():
                    w.writerow([nombre] + [f"{vals[t]:.1f}" for t in tams])
            grafico_openssl(res, CARPETA / "rendimiento_openssl.png", subt)
            print(f"Guardado: {CARPETA / 'rendimiento_openssl.png'}")

    # Mensaje final de interpretación
    print("\nRecuerda: los números dependen de tu CPU. Con AES-NI, AES-GCM suele ganar;")
    print("sin AES-NI (CPU antigua o VM sin la extensión), ChaCha20-Poly1305 suele ganar.")


# Ejecuta main() solo si el archivo se corre directamente (no si se importa desde otro script)
if __name__ == "__main__":
    main()