"""Independent offline acceptance; product imported only from frozen replay."""
import io, logging, socket, threading, traceback
from concurrent.futures import ThreadPoolExecutor
import pytest
from review_crypto import Signer, ath, b64
from authlib.oauth2.rfc6749 import OAuth2Request, ResourceProtector, OAuth2Error
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc9449 import DPoPProtection, DPoPTokenValidator, InvalidDPoPProofError

TOKEN='review-synthetic-access-A'
URL='https://api.example.invalid/files'
class Token:
    def __init__(self,jkt): self.jkt=jkt; self.expired=False; self.revoked=False; self.scope='read'
    def is_expired(self): return self.expired
    def is_revoked(self): return self.revoked
    def get_scope(self): return self.scope
class Store:
    def __init__(self,clock): self.clock=clock; self.rows={}; self.calls=[]; self.lock=threading.Lock(); self.error=None
    def register_proof_confirmation(self,jkt,jti,expires_at):
        with self.lock:
            self.calls.append((jkt,jti,expires_at))
            if self.error: raise RuntimeError(self.error)
            # Inclusive validity endpoint: retain until strictly after expiry.
            self.rows={k:v for k,v in self.rows.items() if v>=self.clock()}
            key=(jkt,jti)
            if key in self.rows: return False
            self.rows[key]=expires_at; return True
class World:
    def __init__(self):
        self.now=1000000; self.signer=Signer(); self.clock=lambda:self.now
        self.store=Store(self.clock); self.token=Token(self.signer.thumbprint)
        self.tokens={TOKEN:self.token,'review-synthetic-access-B':Token(self.signer.thumbprint),'unbound':Token(None)}
        tokens=self.tokens
        class V(DPoPTokenValidator):
            def authenticate_token(self,string):return tokens.get(string)
            def get_token_confirmation(self,token):return token.jkt if token else None
        class B(BearerTokenValidator):
            def authenticate_token(self,string):return tokens.get(string)
        self.validator=V(replay_store=self.store,proof_max_age=60,clock_skew=10,clock=self.clock)
        self.rp=ResourceProtector(); self.rp.register_token_validator(self.validator); self.rp.register_token_validator(B()); self.rp.register_extension(DPoPProtection())
        self.legacy=ResourceProtector(); self.legacy.register_token_validator(B())
    def claims(self,**changes):
        c=self.signer.claims(token=TOKEN,now=int(self.now),uri=URL);c.update(changes);return c
    def proof(self,claims=None,header=None,signer=None):return (signer or self.signer).sign(self.claims() if claims is None else claims,header)
    def request(self,proof,token=TOKEN,method='GET',uri=URL,scheme='DPoP',legacy=False,scopes=None):
        h={'Authorization':scheme+' '+token}
        if proof is not None:h['DPoP']=proof
        return (self.legacy if legacy else self.rp).validate_request(['read'] if scopes is None else scopes,OAuth2Request(method,uri,headers=h))
@pytest.fixture
def w():return World()
@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def deny(*a,**k):raise AssertionError('Network access forbidden during offline acceptance')
    monkeypatch.setattr(socket.socket,'connect',deny);monkeypatch.setattr(socket,'create_connection',deny)

def reject_and_recover(w,proof,**kwargs):
    with pytest.raises(OAuth2Error):w.request(proof,**kwargs)
    assert not w.store.calls,'Invalid request consumed replay identifier'
    assert w.request(w.proof()) is w.token

def test_valid_real_signature_and_single_use(w):
    p=w.proof();assert w.request(p) is w.token
    assert w.store.calls==[(w.signer.thumbprint,'single-use-1',1000070)]
    with pytest.raises(InvalidDPoPProofError):w.request(p)

def test_signature_tamper(w):
    p=w.proof().split('.');import base64
    s=base64.urlsafe_b64decode(p[2]+'==');p[2]=b64(bytes([s[0]^1])+s[1:])
    reject_and_recover(w,'.'.join(p))

def test_other_key_rejected(w):reject_and_recover(w,w.proof(signer=Signer()))
@pytest.mark.parametrize('field,value',[('ath','wrong'),('ath','\u4e0d\u662fASCII'),('htm','POST'),('htu',URL+'/other'),('jti',''),('jti',7),('iat',True),('iat',1000000.0),('iat','1000000'),('ath',None),('htm',7),('htu',7)])
def test_bad_claims_do_not_consume(w,field,value):reject_and_recover(w,w.proof(w.claims(**{field:value})))
@pytest.mark.parametrize('field',['jti','iat','htm','htu','ath'])
def test_required_claim(w,field):
    c=w.claims();del c[field];reject_and_recover(w,w.proof(c))
@pytest.mark.parametrize('header',[{'typ':'JWT'},{'alg':'none'},{'alg':'HS256'},{'jku':'https://keys.example.invalid/jwk'},{'x5u':'https://keys.example.invalid/cert'},{'jwk':{'kty':'oct','k':'AA'}}])
def test_disallowed_header_no_download(w,header):reject_and_recover(w,w.proof(header=header))
def test_private_jwk(w):
    n=w.signer.key.private_numbers().private_value;jwk=dict(w.signer.jwk,d=b64(n.to_bytes(32,'big')))
    reject_and_recover(w,w.proof(header={'jwk':jwk}))
@pytest.mark.parametrize('proof',['not-jwt',None,''])
def test_missing_malformed_proof(w,proof):reject_and_recover(w,proof)
@pytest.mark.parametrize('offset,allowed',[(-71,False),(-70,True),(10,True),(11,False)])
def test_injected_time_endpoints(w,offset,allowed):
    p=w.proof(w.claims(iat=w.now+offset))
    if allowed:assert w.request(p) is w.token
    else:reject_and_recover(w,p)
@pytest.mark.parametrize('claimed,actual',[
    ('HTTPS://API.EXAMPLE.INVALID:443/files?proof=1#x',URL+'?request=2#y'),
    ('http://API.EXAMPLE.INVALID:80/files?x','http://api.example.invalid/files#z')])
def test_url_equivalence(w,claimed,actual):assert w.request(w.proof(w.claims(htu=claimed)),uri=actual) is w.token
@pytest.mark.parametrize('claimed,actual',[(URL.upper(),URL),(URL+'%2Fname',URL+'/name'),(URL+':abc',URL),('https://api.example.invalid:444/files',URL)])
def test_distinct_path_port(w,claimed,actual):reject_and_recover(w,w.proof(w.claims(htu=claimed)),uri=actual)
@pytest.mark.parametrize('state',['expired','revoked','scope'])
def test_bad_token_state_no_registration(w,state):
    setattr(w.token,state,'' if state=='scope' else True)
    with pytest.raises(OAuth2Error):w.request(w.proof())
    assert not w.store.calls
    setattr(w.token,state,'read' if state=='scope' else False)
    assert w.request(w.proof()) is w.token

def test_token_switch_ath(w):reject_and_recover(w,w.proof(),token='review-synthetic-access-B')
def test_unknown_token(w):reject_and_recover(w,w.proof(),token='unknown')
def test_bearer_bypass_and_legacy_compatibility(w):
    with pytest.raises(OAuth2Error):w.request(None,scheme='Bearer')
    assert not w.store.calls
    assert w.request(None,scheme='Bearer',legacy=True) is w.token
    assert w.request(None,token='unbound',scheme='Bearer') is w.tokens['unbound']

def test_two_threads_only_one_accepts(w):
    p=w.proof();barrier=threading.Barrier(2)
    def work(_):
        barrier.wait()
        try:w.request(p);return 'accepted'
        except OAuth2Error:return 'rejected'
    with ThreadPoolExecutor(2) as pool:out=list(pool.map(work,range(2)))
    assert sorted(out)==['accepted','rejected'];assert len(w.store.rows)==1

def test_storage_failure_rejects_then_recovery(w):
    w.store.error='offline synthetic store unavailable'
    with pytest.raises(InvalidDPoPProofError):w.request(w.proof())
    assert not w.store.rows
    w.store.error=None;assert w.request(w.proof()) is w.token

def test_future_proof_record_covers_remaining_window(w):
    p=w.proof(w.claims(iat=w.now+10));assert w.request(p) is w.token
    assert w.store.calls[-1][2]==1000080
    w.now=1000080
    with pytest.raises(InvalidDPoPProofError):w.request(p)
    w.now+=1
    with pytest.raises(InvalidDPoPProofError):w.request(p)
    assert len(w.store.calls)==2,'Expired proof should not reach replay store'

def test_debug_logs_do_not_disclose_token_or_complete_proof(w,caplog):
    p=w.proof();w.store.error='synthetic callback failure: '+TOKEN+' '+p
    caplog.set_level(logging.DEBUG)
    with pytest.raises(InvalidDPoPProofError):w.request(p)
    assert TOKEN not in caplog.text,'DEBUG logs disclosed the synthetic access token'
    assert p not in caplog.text,'DEBUG logs disclosed the complete signed proof'

def test_formatted_exception_does_not_disclose_token_or_proof(w):
    p=w.proof();w.store.error='synthetic callback failure: '+TOKEN+' '+p
    try:w.request(p)
    except InvalidDPoPProofError as exc:rendered=''.join(traceback.format_exception(exc))
    else:pytest.fail('Storage failure accepted')
    assert TOKEN not in rendered,'Exception chain disclosed the synthetic access token'
    assert p not in rendered,'Exception chain disclosed the complete signed proof'
