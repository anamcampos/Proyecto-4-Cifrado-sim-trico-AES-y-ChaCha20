#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EXPERIMENTO 2 - Manipulación de archivos cifrados

Idea: un atacante que NO conoce la llave cambia UN solo byte del archivo cifrado.
  * Con modos que autentican (AES-GCM, ChaCha20-Poly1305) el descifrado FALLA y
    cifrador.py reporta la manipulación (código de salida 2).
  * Con modos sin autenticación (AES-CTR, AES-ECB) el descifrado "funciona",
    pero entrega datos alterados SIN avisar nada.

El experimento usa la herramienta real (cifrador.py) mediante subprocess, así
ves exactamente lo que verías tú en la terminal.

Uso:
    python3 experimento2_manipulacion.py

Salida: carpeta resultados/exp2/ (archivos cifrados, alterados y resumen.txt)
"""

import shutil
import subprocess
import sys
from pathlib import Path

CARPETA = Path("resultados/exp2")
CIFRADOR = Path(__file__).resolve().parent / "cifrador.py"
MENSAJE = "ORDEN DE PAGO: transferir 100 colones a Ana. Cuenta destino: 123-456."
TAM_CABECERA = 6          # "CIFR" + versión + modo
TAM_NONCE = {"gcm": 12, "chacha20": 12, "ctr": 16, "ecb": 0}

lineas_resumen = []       # todo lo que se imprime también se guarda en resumen.txt


def decir(texto: str = "") -> None:
    print(texto)
    lineas_resumen.append(texto)


def cifrador(*args: str) -> subprocess.CompletedProcess:
    """Ejecuta cifrador.py como lo haría una persona en la terminal y muestra el resultado."""
    decir("$ python3 cifrador.py " + " ".join(args))
    r = subprocess.run([sys.executable, str(CIFRADOR), *args], capture_output=True, text=True)
    for linea in (r.stdout + r.stderr).splitlines():
        decir("  " + linea)
    decir(f"  (código de salida: {r.returncode})")
    return r


def alterar_un_byte(origen: Path, destino: Path, posicion: int, xor: int) -> None:
    """Copia 'origen' a 'destino' cambiando UN byte: byte_nuevo = byte_viejo XOR xor."""
    datos = bytearray(origen.read_bytes())
    decir(f"  >> Atacante: byte #{posicion} pasa de 0x{datos[posicion]:02x} a 0x{datos[posicion] ^ xor:02x}")
    datos[posicion] ^= xor
    destino.write_bytes(datos)


def probar_modo(modo: str, posicion_texto: int, xor: int) -> dict:
    """Cifra, altera un byte del texto cifrado e intenta descifrar."""
    decir()
    decir("=" * 72)
    decir(f"MODO: {modo}")
    decir("=" * 72)
    llave, original = CARPETA / f"{modo}.key", CARPETA / "mensaje.txt"
    cifrado, alterado = CARPETA / f"mensaje_{modo}.enc", CARPETA / f"mensaje_{modo}_ALTERADO.enc"
    recuperado = CARPETA / f"recuperado_{modo}.txt"

    cifrador("generar-llave", "--modo", modo, "--llave", str(llave))
    cifrador("cifrar", "--modo", modo, "--llave", str(llave), "-i", str(original), "-o", str(cifrado))

    decir()
    decir("-- 1) Descifrado normal (sin tocar el archivo) --")
    cifrador("descifrar", "--llave", str(llave), "-i", str(cifrado), "-o", str(CARPETA / f"sano_{modo}.txt"))

    decir()
    decir("-- 2) Atacante cambia UN byte del archivo cifrado --")
    # El texto cifrado empieza después de la cabecera y el nonce.
    alterar_un_byte(cifrado, alterado, TAM_CABECERA + TAM_NONCE[modo] + posicion_texto, xor)

    decir()
    decir("-- 3) Descifrado del archivo alterado --")
    r = cifrador("descifrar", "--llave", str(llave), "-i", str(alterado), "-o", str(recuperado))

    if r.returncode == 0:
        texto = recuperado.read_text(errors="replace")
        texto = "".join(c if c.isprintable() else "?" for c in texto)   # oculta caracteres de control raros
        decir(f"  Texto original : {MENSAJE}")
        decir(f"  Texto recibido : {texto}")
        return {"modo": modo, "detecta": False, "resultado": texto}
    return {"modo": modo, "detecta": True, "resultado": "descifrado rechazado (sin archivo de salida)"}


def main() -> None:
    if CARPETA.exists():
        shutil.rmtree(CARPETA)           # empezamos limpio
    CARPETA.mkdir(parents=True)
    (CARPETA / "mensaje.txt").write_text(MENSAJE)

    # Posición del primer '1' de "100": lo usamos para el ataque dirigido.
    pos_uno = MENSAJE.index("100")
    # En modos tipo flujo (CTR), cambiar el texto cifrado con XOR cambia el texto claro con el mismo XOR:
    # '1' XOR '9' = el cambio justo para convertir "100" en "900".
    xor_1_a_9 = ord("1") ^ ord("9")

    resultados = [
        probar_modo("gcm", pos_uno, xor_1_a_9),
        probar_modo("chacha20", pos_uno, xor_1_a_9),
        probar_modo("ctr", pos_uno, xor_1_a_9),
        probar_modo("ecb", 3, 0x01),      # en ECB un cambio en el bloque 1 estropea ese bloque completo
    ]

    decir()
    decir("=" * 72)
    decir("RESUMEN")
    decir("=" * 72)
    decir(f"{'Modo':<10}{'¿Detectó la manipulación?':<28}Qué pasó")
    detalle = {"ctr": "el texto dice 900 colones en vez de 100",
               "ecb": "un bloque de 16 bytes quedó como basura"}
    for r in resultados:
        decir(f"{r['modo']:<10}{('SI (rechazó el archivo)' if r['detecta'] else 'NO (aceptó datos alterados)'):<28}"
              f"{'' if r['detecta'] else detalle.get(r['modo'], 'datos alterados')}")
    decir()
    decir("Conclusión: cifrar NO es lo mismo que proteger la integridad. Usa GCM o ChaCha20-Poly1305.")

    (CARPETA / "resumen.txt").write_text("\n".join(lineas_resumen), encoding="utf-8")
    print(f"\nResumen guardado en {CARPETA / 'resumen.txt'}")


if __name__ == "__main__":
    main()
