from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography. hazmat.primitives.ciphers import Cipher, algorithms, modes

import os
import argparse
import getpass

def generar_llave(password: str, salt: bytes):
    """
    Función para derivar una llave a partir de un password.

    Keyword Arguments:
    password: str
    salt: bytes
    returns: bytes
    """
    password_bin = password.encode('utf-8')
    kdf = Scrypt(salt=salt, length = 32, n =2**14, r =8, p=1, backend=default_backend())
    key = kdf.derive(password_bin)
    return key

def cifrar(inputPath: str, outPath: str, password: str):
    """
    Cifrar un archivo con AES GCM.

    Keyword Arguments:
    inputPath ruta de archivo plano a cifrar
    outputPath ruta del archivo cifrado resultante
    password  str
    returns: None, crea un achivo
    """
    iv = os.urandom(12)
    salt = os.urandom(16)
    key = generar_llave(password, salt)
    datos_adicionales = iv + salt

    encryptor = Cipher(algorithms.AES(key),
                       modes.GCM(iv),
                       backend = default_backend()).encryptor()

    encryptor.authenticate_additional_data(datos_adicionales)

    salida = open(outPath, 'bw')
    for buffer in open(inputPath, 'rb'):
        cifrado = encryptor.update(buffer)
        salida.write(cifrado)

    encryptor.finalize()
    tag = encryptor.tag

    salida.write(iv) # 12 bytes
    salida.write(salt) # 16 bytes
    salida.write(tag) # 16 bytes
    salida.close()

def dividir_llaves(union):
    datos=union[-44:]
    iv=datos[:-32]
    salt=datos[12:][:16]
    tag=datos[28:]

    return iv,salt,tag

def descifrar(inputPath: str, outPath: str, password: str):
    for buffer in open(inputPath, 'rb'):
        cifrado = buffer

    iv,salt,tag = dividir_llaves(cifrado)
    key = generar_llave(password, salt)

    decryptor = Cipher(algorithms.AES(key),
                    modes.GCM(iv, tag),
                    backend = default_backend()).decryptor()

    associated_data = iv + salt
    decryptor.authenticate_additional_data(associated_data)
    #se reescribe el archivo de entrada para quitar las llaves
    size = os.path.getsize(inputPath) #Verifica el tamaño de la ruta de entrada y la devuelve en byte
    with open(inputPath, 'r+') as s:
        s.truncate(size - 44)
    s.close()

    salida = open(outPath, 'bw')
    for buffer in open(inputPath, 'rb'):
        texto_plano = decryptor.update(buffer)
        salida.write(texto_plano)

    salida.close()

    #Al final vuelve a reescribir y pegar las llaves que quitamos del archivo cifrado
    final = open(inputPath, 'ba') #modo ba añade cosas al final del archivo sin borrar su contenido
    final.write(iv) # 12 bytes
    final.write(salt) # 16 bytes
    final.write(tag) # 16 bytes
    final.close()

    try:
        decryptor.finalize()
        print ('El archivo no fue comprometido');
    except:
        print('No pasó la verificación de tag, integridad comprometida')

if __name__ == '__main__':
    all_args =  argparse.ArgumentParser()
    all_args.add_argument("-p", "--Operacion", help="Aplicar operación, cifrar/descifrar")
    all_args.add_argument("-i", "--input", help="Archivo de entrada", required=True)
    all_args.add_argument("-o", "--output", help="Archivo de salida", required=True)
    args = vars(all_args.parse_args())
    operacion = args['Operacion']
    password = getpass.getpass(prompt='Password: ')
    if operacion == 'cifrar':
        cifrar(args['input'], args['output'], password)
    elif operacion == 'descifrar':
        descifrar(args['input'], args['output'], password)
    else:
        print("No se mando un modo de operación valido")
