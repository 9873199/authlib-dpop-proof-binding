"""Independent reviewer crypto fixture. Keys are generated in memory, never saved."""
import base64,hashlib,json,time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

def b64(data):return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')
def ath(token):return b64(hashlib.sha256(token.encode('ascii')).digest())
def compact_json(obj):return json.dumps(obj,separators=(',',':'),sort_keys=True).encode('utf-8')
class Signer:
 def __init__(self):self.key=ec.generate_private_key(ec.SECP256R1())
 @property
 def jwk(self):
  p=self.key.public_key().public_numbers()
  return {'kty':'EC','crv':'P-256','x':b64(p.x.to_bytes(32,'big')),'y':b64(p.y.to_bytes(32,'big'))}
 @property
 def thumbprint(self):return b64(hashlib.sha256(compact_json(self.jwk)).digest())
 def sign(self,claims,header=None):
  h={'alg':'ES256','typ':'dpop+jwt','jwk':self.jwk};h.update(header or {})
  message=(b64(compact_json(h))+'.'+b64(compact_json(claims))).encode('ascii')
  der=self.key.sign(message,ec.ECDSA(hashes.SHA256()));r,s=decode_dss_signature(der)
  return message.decode('ascii')+'.'+b64(r.to_bytes(32,'big')+s.to_bytes(32,'big'))
 def claims(self,token='access-A',jti='single-use-1',now=1000000,method='GET',uri='https://api.example.invalid/files'):
  return {'jti':jti,'iat':now,'htm':method,'htu':uri,'ath':ath(token)}

def fixture_self_check():
 # Cross-check the reviewer's direct cryptography signer with the dependency's
 # decoder and RFC7638 thumbprint implementation; not an Authlib DPoP test.
 from joserfc import jwt
 from joserfc.jwk import ECKey
 from joserfc.errors import JoseError
 signer=Signer();claims={'fixture_control':'offline'};proof=signer.sign(claims)
 key=ECKey.import_key(signer.jwk)
 assert key.thumbprint()==signer.thumbprint
 assert jwt.decode(proof,key,algorithms=['ES256']).claims==claims
 segments=proof.split('.');body=base64.urlsafe_b64decode(segments[2]+'==');damaged=bytes([body[0]^1])+body[1:]
 try:jwt.decode('.'.join([*segments[:2],b64(damaged)]),key,algorithms=['ES256'])
 except JoseError:pass
 else:raise AssertionError('Damaged signature accepted by fixture control')
 print(json.dumps({'fixture_only':'PASS','in_memory_P256':True,'direct_cryptography_signing':True,'dependency_cross_verification':True,'RFC7638_thumbprint_cross_check':True,'tampered_signature_rejected':True,'product_evaluated':False}))
if __name__=='__main__':fixture_self_check()
