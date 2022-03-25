import argparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

if __name__ == '__main__':
    all_args =  argparse.ArgumentParser()
    all_args.add_argument("-c", "--conocida", help="Archivo de salida para llave publica", required=True)
    all_args.add_argument("-p", "--privada", help="Archivo de salida de llave privada", required=True)
    args = vars(all_args.parse_args())


# Generar llave privada
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Extraer llave publica de llave privada
public_key = private_key.public_key()

# Convertir llave privada a bytes, sin cifrar los bytes
# Obviamente a partir de los bytes se puede guardar en un archivo binario
private_key_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

path_privada = args['privada']
salida = open(path_privada, 'wb')
salida.write(private_key_bytes)
salida.close()

# Convertir la llave publica en bytes
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

path_publica = args['conocida']
salida = open(path_publica, 'wb')
salida.write(private_key_bytes)
salida.close()


