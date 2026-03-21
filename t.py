import GNServer

from GNServer import response, GNRequest, GNResponse



# dp = 'example.com'

# r = response.app.NotFound(f'No active nodes found for domain pattern: {dp}')




# if not r.command.ok:
#     print('Not ok')


# print(r.command.ok)


# from gnobjects.net.tools import DomainMatcherList, DomainMatcher 

# from gnobjects.net.values import gn_core_domains

# x = [
#     '*~rgate.gn',
#     'planner.rgate.*~rcms.gn',
#     *['**.' + d for d in gn_core_domains],
#     *['**~' + d for d in gn_core_domains]
# ]
# d = DomainMatcherList(x)

# print(x)

# print(d.match_any('core.dns.1~rcms.gn'))


from KeyisBTools.models.serialization import deserialize, serialize

import datetime



# t = datetime.datetime.now(datetime.timezone.utc)


# print(t)
# s = serialize({'123': [t, t, t], t: '123'})
# print(s)
# t2 = deserialize(s)
# print(t2)




from gnobjects.net.objects import TempDataObject


t = TempDataObject('html', b'<html><body>Hello, World!</body></html>')

c = t.container

nt = TempDataObject(c)

s = nt.serialize()

des = TempDataObject.deserialize(s)


print(des)