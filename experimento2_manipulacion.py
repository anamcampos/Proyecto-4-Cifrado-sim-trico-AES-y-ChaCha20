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

import shutil       # para borrar carpetas completas (shutil.rmtree)
import subprocess   # para ejecutar cifrador.py como si fuera un comando de terminal
import sys          # para obtener el intérprete de Python actual (sys.executable)
from pathlib import Path  # manejo cómodo de rutas de archivos y carpetas

# Carpeta donde se guardarán todos los resultados del experimento
CARPETA = Path("resultados/exp2")
# Ruta absoluta a cifrador.py, que debe estar en la misma carpeta que este script
CIFRADOR = Path(__file__).resolve().parent / "cifrador.py"
# Mensaje de ejemplo que se cifrará y se intentará alterar
MENSAJE = "ORDEN DE PAGO: transferir 100 colones a Ana. Cuenta destino: 123-456."
TAM_CABECERA = 6          # "CIFR" + versión + modo
# Tamaño en bytes del nonce que cifrador.py guarda tras la cabecera, según el modo
TAM_NONCE = {"gcm": 12, "chacha20": 12, "ctr": 16, "ecb": 0}

lineas_resumen = []       # todo lo que se imprime también se guarda en resumen.txt


def decir(texto: str = "") -> None:
    # Muestra el texto en pantalla...
    print(texto)
    # ...y lo guarda en la lista para escribirlo luego en resumen.txt
    lineas_resumen.append(texto)


def cifrador(*args: str) -> subprocess.CompletedProcess:
    """Ejecuta cifrador.py como lo haría una persona en la terminal y muestra el resultado."""
    # Muestra el comando que se va a ejecutar, con el prefijo "$" típico de terminal
    decir("$ python3 cifrador.py " + " ".join(args))
    # Ejecuta cifrador.py con el mismo Python; capture_output guarda stdout y stderr, text=True los da como texto
    r = subprocess.run([sys.executable, str(CIFRADOR), *args], capture_output=True, text=True)
    # Imprime línea por línea la salida normal y los errores, con sangría
    for linea in (r.stdout + r.stderr).splitlines():
        decir("  " + linea)
    # Muestra el código de salida (0 = éxito; otro valor = error)
    decir(f"  (código de salida: {r.returncode})")
    # Devuelve el resultado para que quien llamó pueda revisar el código de salida
    return r


def alterar_un_byte(origen: Path, destino: Path, posicion: int, xor: int) -> None:
    """Copia 'origen' a 'destino' cambiando UN byte: byte_nuevo = byte_viejo XOR xor."""
    # Lee el archivo completo como bytearray (a diferencia de bytes, se puede modificar)
    datos = bytearray(origen.read_bytes())
    # Informa qué byte se va a cambiar, mostrando valor viejo y nuevo en hexadecimal
    decir(f"  >> Atacante: byte #{posicion} pasa de 0x{datos[posicion]:02x} a 0x{datos[posicion] ^ xor:02x}")
    # Aplica el cambio: XOR del byte con el valor dado
    datos[posicion] ^= xor
    # Guarda la versión alterada en un archivo nuevo (el original queda intacto)
    destino.write_bytes(datos)


def probar_modo(modo: str, posicion_texto: int, xor: int) -> dict:
    """Cifra, altera un byte del texto cifrado e intenta descifrar."""
    # Encabezado visual para separar cada modo en la salida
    decir()
    decir("=" * 72)
    decir(f"MODO: {modo}")
    decir("=" * 72)
    # Rutas de los archivos de llave y de mensaje original
    llave, original = CARPETA / f"{modo}.key", CARPETA / "mensaje.txt"
    # Rutas del archivo cifrado y de su versión alterada por el atacante
    cifrado, alterado = CARPETA / f"mensaje_{modo}.enc", CARPETA / f"mensaje_{modo}_ALTERADO.enc"
    # Ruta donde se guardará lo que salga del descifrado del archivo alterado
    recuperado = CARPETA / f"recuperado_{modo}.txt"

    # Genera una llave nueva para este modo
    cifrador("generar-llave", "--modo", modo, "--llave", str(llave))
    # Cifra el mensaje con ese modo y esa llave
    cifrador("cifrar", "--modo", modo, "--llave", str(llave), "-i", str(original), "-o", str(cifrado))

    decir()
    decir("-- 1) Descifrado normal (sin tocar el archivo) --")
    # Prueba de control: el archivo sin alterar debe descifrarse bien
    cifrador("descifrar", "--llave", str(llave), "-i", str(cifrado), "-o", str(CARPETA / f"sano_{modo}.txt"))

    decir()
    decir("-- 2) Atacante cambia UN byte del archivo cifrado --")
    # El texto cifrado empieza después de la cabecera y el nonce.
    # Sumamos cabecera + nonce + posición dentro del texto para llegar al byte exacto
    alterar_un_byte(cifrado, alterado, TAM_CABECERA + TAM_NONCE[modo] + posicion_texto, xor)

    decir()
    decir("-- 3) Descifrado del archivo alterado --")
    # Intenta descifrar el archivo manipulado y guarda el resultado de la ejecución
    r = cifrador("descifrar", "--llave", str(llave), "-i", str(alterado), "-o", str(recuperado))

    # Código 0 = el descifrado "funcionó": el modo NO detectó la manipulación
    if r.returncode == 0:
        # Lee el texto recuperado; errors="replace" evita fallos con bytes inválidos
        texto = recuperado.read_text(errors="replace")
        texto = "".join(c if c.isprintable() else "?" for c in texto)   # oculta caracteres de control raros
        # Compara lo que se envió con lo que se recibió
        decir(f"  Texto original : {MENSAJE}")
        decir(f"  Texto recibido : {texto}")
        return {"modo": modo, "detecta": False, "resultado": texto}
    # Código distinto de 0 = el descifrado fue rechazado: se detectó la manipulación
    return {"modo": modo, "detecta": True, "resultado": "descifrado rechazado (sin archivo de salida)"}


def main() -> None:
    # Si la carpeta de resultados ya existe, se borra entera
    if CARPETA.exists():
        shutil.rmtree(CARPETA)           # empezamos limpio
    # Crea la carpeta (con sus padres si hacen falta)
    CARPETA.mkdir(parents=True)
    # Escribe el mensaje de ejemplo en un archivo de texto
    (CARPETA / "mensaje.txt").write_text(MENSAJE)

    # Posición del primer '1' de "100": lo usamos para el ataque dirigido.
    pos_uno = MENSAJE.index("100")
    # En modos tipo flujo (CTR), cambiar el texto cifrado con XOR cambia el texto claro con el mismo XOR:
    # '1' XOR '9' = el cambio justo para convertir "100" en "900".
    xor_1_a_9 = ord("1") ^ ord("9")

    # Prueba los cuatro modos y junta los resultados en una lista
    resultados = [
        probar_modo("gcm", pos_uno, xor_1_a_9),
        probar_modo("chacha20", pos_uno, xor_1_a_9),
        probar_modo("ctr", pos_uno, xor_1_a_9),
        probar_modo("ecb", 3, 0x01),      # en ECB un cambio en el bloque 1 estropea ese bloque completo
    ]

    # --- Tabla de resumen final ---
    decir()
    decir("=" * 72)
    decir("RESUMEN")
    decir("=" * 72)
    # Encabezado de la tabla con columnas alineadas (<10 y <28 son anchos en caracteres)
    decir(f"{'Modo':<10}{'¿Detectó la manipulación?':<28}Qué pasó")
    # Explicación de qué pasó en los modos que NO detectan la alteración
    detalle = {"ctr": "el texto dice 900 colones en vez de 100",
               "ecb": "un bloque de 16 bytes quedó como basura"}
    # Una fila por modo: SI/NO según detectó, y el detalle solo si no detectó
    for r in resultados:
        decir(f"{r['modo']:<10}{('SI (rechazó el archivo)' if r['detecta'] else 'NO (aceptó datos alterados)'):<28}"
              f"{'' if r['detecta'] else detalle.get(r['modo'], 'datos alterados')}")
    decir()
    decir("Conclusión: cifrar NO es lo mismo que proteger la integridad. Usa GCM o ChaCha20-Poly1305.")

    # Guarda todo lo impreso en resumen.txt, con codificación UTF-8 para los acentos
    (CARPETA / "resumen.txt").write_text("\n".join(lineas_resumen), encoding="utf-8")
    print(f"\nResumen guardado en {CARPETA / 'resumen.txt'}")


# Ejecuta main() solo si el archivo se corre directamente (no si se importa desde otro script)
if __name__ == "__main__":
    main()