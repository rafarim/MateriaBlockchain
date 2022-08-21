from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as EDPK
from cryptography.exceptions import InvalidSignature

# • Que cria uma chave publica e privada usando o RSA
def Generate_Keys():
  keys = {}
  keys['PrivKey'] = EDPK.generate()
  keys['PubKey'] = keys['PrivKey'].public_key()
  return keys

# • Uma função que assina uma mensagem usando a chave privada
def Sign_Message(message, keys):
  return keys['PrivKey'].sign(bytes(message, 'utf-8'))

# • Outra função que verifica se a mensagem foi assinada de forma correta
def Verify_Message(message, signature, keys):
  try:
    keys['PubKey'].verify(signature, bytes(message, 'utf-8'))
    return True
  except InvalidSignature:
    return False

if __name__ == "__main__":
  chaves = Generate_Keys()
  mensagem = 'Oi, bom dia'
  assinatura = Sign_Message(mensagem, chaves)
  print(Verify_Message(mensagem, assinatura, chaves))
  print(Verify_Message(mensagem+'qweuhuh', assinatura, chaves))
