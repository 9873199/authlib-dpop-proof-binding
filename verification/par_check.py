"""Additional PAR contract probes, using only the model's thin local transport fixtures."""
import json,threading,traceback
from urllib.parse import urlparse
from tests.core.test_oauth2 import test_rfc9126 as t
from authlib.oauth2.rfc9126 import MemoryPushedAuthorizationStorage,handle_from_request_uri
from authlib.oauth2.rfc7636 import create_s256_code_challenge

def setup(storage=None):
 clock={'now':1000.0};storage=storage or MemoryPushedAuthorizationStorage(time_func=lambda:clock['now'])
 server=t.LocalAuthorizationServer(storage,expires_in=60);server.add_client(t.TestClient());server.add_client(t.TestClient(client_id=t.OTHER_CLIENT_ID))
 return clock,storage,server,t.ParLocalClient(server)

def handle(storage,response):
 assert response.status_code==201,response.body
 uri=response.body['request_uri'];return uri,storage.get(handle_from_request_uri(uri))

def authenticated_roundtrip():
 _,store,s,c=setup();uri,_=handle(store,c.push());r=c.decide(uri);assert r.status_code==303 and s.issue_count==1;return {'issued':s.issue_count,'status':r.status_code}
def refresh_does_not_consume():
 _,store,s,c=setup();uri,before=handle(store,c.push())
 for _ in range(5):assert not isinstance(c.open_authorize(uri),t.LocalResponse)
 after=store.get(before.handle);assert (after.status,after.version)==('active',before.version) and s.issue_count==0;return {'refreshes':5,'status':after.status,'issued':s.issue_count}
def parameter_tampering():
 outcomes={}
 for name,value in [('scope','profile'),('redirect_uri','https://other.invalid/cb'),('code_challenge','B'*43),('state','changed')]:
  _,store,s,c=setup();uri,record=handle(store,c.push());r=c.decide(uri,extra={name:value});assert r.status_code==400 and s.issue_count==0;assert store.get(record.handle).status=='active';outcomes[name]=r.body['error']
 return outcomes
def cross_client():
 _,store,s,c=setup();uri,_=handle(store,c.push());r=c.decide(uri,client_id=t.OTHER_CLIENT_ID);assert r.status_code==400 and s.issue_count==0;return {'error':r.body['error'],'issued':0}
def bad_secret():
 _,store,s,c=setup();r=c.push(client_secret='wrong');assert r.status_code==401 and not store._records;return {'status':401,'records':0}
def exact_redirect():
 _,store,s,c=setup();r=c.push({'redirect_uri':t.REDIRECT_URI+'?different=1'});assert r.status_code==400 and not store._records;return {'status':400,'records':0}
def pkce_token():
 _,store,s,c=setup();verifier='A'*64;uri,_=handle(store,c.push({'code_challenge':create_s256_code_challenge(verifier),'code_challenge_method':'S256'}));r=c.decide(uri);code=r.query()['code'];bad=c.exchange_code(code,code_verifier='B'*64);assert bad.status_code==400;good=c.exchange_code(code,code_verifier=verifier);assert good.status_code==200;return {'wrong_verifier':bad.status_code,'right_verifier':good.status_code}
def expiry_boundary():
 clock,store,s,c=setup();uri,record=handle(store,c.push());clock['now']=record.expires_at; r=c.decide(uri);assert r.status_code==400 and s.issue_count==0;return {'status':400,'issued':0}
def parallel_confirm():
 class BarrierStore(MemoryPushedAuthorizationStorage):
  def __init__(self):super().__init__(time_func=lambda:1000);self.barrier=threading.Barrier(2,timeout=10)
  def consume(self,*args,**kw):self.barrier.wait();return super().consume(*args,**kw)
 _,store,s,c=setup(BarrierStore());uri,_=handle(store,c.push());out=[];errors=[]
 def confirm():
  try:out.append(c.decide(uri).status_code)
  except Exception as e:errors.append(type(e).__name__)
 threads=[threading.Thread(target=confirm) for _ in range(2)]
 for thread in threads:thread.start()
 for thread in threads:thread.join(15)
 assert not errors and sorted(out)==[303,400] and s.issue_count==1 and len(s.codes)==1,(out,errors,s.issue_count)
 return {'statuses':sorted(out),'issued':s.issue_count}
def denied_terminal():
 _,store,s,c=setup();uri,record=handle(store,c.push());denied=c.decide(uri,approved=False);again=c.decide(uri);assert denied.status_code==303 and again.status_code==400 and s.issue_count==0 and store.get(record.handle).decision=='denied';return {'denied':303,'retry':400,'issued':0}
def callback_failure_terminal():
 _,store,s,c=setup();uri,record=handle(store,c.push());s.fail_code_save=True;r=c.decide(uri);s.fail_code_save=False;again=c.decide(uri);assert r.status_code==500 and again.status_code==400 and store.get(record.handle).status=='failed' and s.issue_count==0;return {'first':500,'retry':400,'status':'failed'}
def temporary_storage_failure():
 class Flaky(MemoryPushedAuthorizationStorage):
  def __init__(self):super().__init__(time_func=lambda:1000);self.fail=True
  def consume(self,*args,**kwargs):
   if self.fail:self.fail=False;raise RuntimeError('synthetic temporary storage outage')
   return super().consume(*args,**kwargs)
 _,store,s,c=setup(Flaky());uri,rec=handle(store,c.push());first=c.decide(uri);between=store.get(rec.handle);second=c.decide(uri);assert first.status_code==500 and between.status=='active' and second.status_code==303 and s.issue_count==1;return {'first':500,'retry':303,'issued':1}
def basic_without_body_client_id():
 _,store,s,c=setup();request=t.LocalRequest('POST','/oauth/par',form={'response_type':'code','redirect_uri':t.REDIRECT_URI,'scope':t.SCOPE},headers=t.basic_header());r=s.create_endpoint_response('pushed_authorization',request);actual={'status':r.status_code,'body':r.body};assert r.status_code==201,actual;return actual
def default_redirect_frozen():
 _,store,s,c=setup();client=s.clients[t.CLIENT_ID];other='https://client.example.com/second-cb';client.redirect_uris.append(other)
 request=t.LocalRequest('POST','/oauth/par',form={'response_type':'code','client_id':t.CLIENT_ID,'scope':t.SCOPE},headers=t.basic_header());uri,rec=handle(store,s.create_endpoint_response('pushed_authorization',request));client.redirect_uris.reverse();r=c.decide(uri);actual={'stored_redirect':rec.params.get('redirect_uri'),'browser_location':r.location,'status':r.status_code,'issued':s.issue_count};assert r.status_code!=303 or r.location.startswith(t.REDIRECT_URI+'?'),actual;return actual

CASES=[authenticated_roundtrip,refresh_does_not_consume,parameter_tampering,cross_client,bad_secret,exact_redirect,pkce_token,expiry_boundary,parallel_confirm,denied_terminal,callback_failure_terminal,temporary_storage_failure,basic_without_body_client_id,default_redirect_frozen]
if __name__=='__main__':
 results=[]
 for fn in CASES:
  try:result=fn();results.append({'case':fn.__name__,'status':'PASS','observed':result})
  except Exception as e:results.append({'case':fn.__name__,'status':'FAIL','exception':type(e).__name__,'detail':str(e)})
 print(json.dumps({'scope':'New contract probes; local transport helpers reused, no model test assertions reused','results':results,'passed':sum(r['status']=='PASS' for r in results),'failed':sum(r['status']=='FAIL' for r in results)},ensure_ascii=False,indent=2))
 raise SystemExit(1 if any(r['status']=='FAIL' for r in results) else 0)
