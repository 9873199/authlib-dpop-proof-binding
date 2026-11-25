import logging
from urllib.parse import urlparse
import par_check as p
logging.disable(logging.CRITICAL)
print('PAR authorization - local runtime check')
print('Normal authorization:', p.authenticated_roundtrip())
print('Page refresh:', p.refresh_does_not_consume())
print('PKCE verification:', p.pkce_token())
print('Concurrent confirmations:', p.parallel_confirm())
print('Callback failure:', p.callback_failure_terminal())
_, store, server, client = p.setup()
registered = server.clients[p.t.CLIENT_ID]
registered.redirect_uris.append('https://client.example.com/second-cb')
request = p.t.LocalRequest('POST', '/oauth/par', form={'response_type':'code', 'client_id':p.t.CLIENT_ID, 'scope':p.t.SCOPE}, headers=p.t.basic_header())
uri, record = p.handle(store, server.create_endpoint_response('pushed_authorization', request))
registered.redirect_uris.reverse()
response = client.decide(uri)
print('Default callback at push: /cb')
print('Stored callback:', record.params.get('redirect_uri'))
print('Callback used at approval:', urlparse(response.location).path)
print('Issued authorization codes:', server.issue_count)
print('FAIL: previous request used the changed default callback')
print('Local synthetic client only; no external OAuth service.')
raise SystemExit(1)
