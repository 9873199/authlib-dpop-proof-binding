import io,logging,sys,traceback
from test_review_dpop import World,TOKEN
w=World();c=w.claims(ath="\u4e0d\u662fASCII")
print("Signed proof with invalid ath:")
try:w.request(w.proof(c));print("  request unexpectedly accepted");ath_ok=False
except TypeError as exc:print("  uncaught "+type(exc).__name__+": "+str(exc));ath_ok=False
except Exception as exc:print("  rejected as "+type(exc).__name__);ath_ok=True
w=World();p=w.proof();w.store.error="synthetic callback failure: "+TOKEN+" "+p
stream=io.StringIO();handler=logging.StreamHandler(stream);logger=logging.getLogger("authlib.oauth2.rfc9449.validator");logger.addHandler(handler);logger.setLevel(logging.DEBUG)
try:w.request(p);rendered=""
except Exception as exc:rendered="".join(traceback.format_exception(exc))
finally:logger.removeHandler(handler)
text=stream.getvalue()
print("Storage failure under DEBUG logging (synthetic data):")
print("  access token present in logs:",TOKEN in text)
print("  complete proof present in logs:",p in text)
print("  access token present in exception chain:",TOKEN in rendered)
print("  complete proof present in exception chain:",p in rendered)
print("Raw synthetic token and proof are intentionally not displayed.")
sys.exit(0 if ath_ok and TOKEN not in text+rendered and p not in text+rendered else 1)
