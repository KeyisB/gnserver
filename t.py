import GNServer

from GNServer import response, GNRequest, GNResponse



dp = 'example.com'

r = response.app.NotFound(f'No active nodes found for domain pattern: {dp}')




if not r.command.ok:
    print('Not ok')


print(r.command.ok)

