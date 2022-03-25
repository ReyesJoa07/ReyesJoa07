from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import argparse

def cifrar(path_entrada, path_salida, archivo_key):
  # Convertir la llave publica de bytes a objeto llave
  llave = open(archivo_key, 'r')
  public_key = serialization.load_pem_public_key(llave, backend=default_backend())
  #Comienza a cifrar
  salida= open(path_salida, 'wb')
  message = open(path_entrada, 'rb')
  ciphertext1 = public_key.encrypt(message, padding.OAEP(mgf = padding.MGF1(algorithm = hashes.SHA256()), algorithm = hashes.SHA256(), label = None)) # se usa rara vez dejar None
  salida.write(ciphertext1)
  salida.close()



def descifrar(path_entrada, path_salida, archivo_key):
  # Convertir la llave privada de bytes a objeto llave
  # Como no se cifraron los bytes no hace falta un password
  llave = open(archivo_key, 'r')
  private_key = serialization.load_pem_private_key(llave, backend=default_backend(), password=None)
  #Comienza el decifrado
  salida= open(path_salida, 'wb')
  plano = open(path_entrada, 'rb')
  recovered1 = private_key.decrypt(plano, padding.OAEP(mgf = padding.MGF1(algorithm = hashes.SHA256()), algorithm = hashes.SHA256(), label = None))
  salida.write(recovered1)
  salida.close()




if __name__ == '__main__':
    all_args =  argparse.ArgumentParser()
    all_args.add_argument("-a", "--accion", help="Aplicar operación, cifrar/descifrar")
    all_args.add_argument("-c", "--conocida", help="Archivo que contiene la llave publica")
    all_args.add_argument("-p", "--privada", help="Archivo que contiene la llave privada")
    all_args.add_argument("-i", "--input", help="Archivo a cifrar", required=True)
    all_args.add_argument("-o", "--output", help="Archivo de salida para el cifrado/decifrado", required=True)
    args = vars(all_args.parse_args())
    accion = args['accion']
    if accion == 'cifrar':
       cifrar(args['input'], args['output'], args['conocida'])
    else:
       descifrar(args['input'], args['output'], args['privada'])
