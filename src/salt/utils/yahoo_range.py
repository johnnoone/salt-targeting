'''

salt.utils.yahoo_range
~~~~~~~~~~~~~~~~~~~~~~

Defines the most of matching.

'''

from salt._compat import PY3
import contextlib

if PY3:
    from urllib import quote, Request, URLError, urlopen

    request_context = urlopen
else:
    from urllib2 import quote, Request, URLError, urlopen
    import contextlib

    def request_context(request):
        return contextlib.closing(urlopen(request))


class RangeException(RuntimeError): pass


class Server(object):
    def __init__(self, host, batch_size=None):
        self.host = host
        self.batch_size = batch_size or 500

    def get(self, query):
        while len(query) > self.batch_size:
            for i in range(self.batch_size, 0, -1):
                if expr[i] == ',':
                    subquery, query = query[0:i], query[i+1:]
                    for fqdn in batch(host, subquery):
                        yield fqdn

        for fqdn in batch(host, query):
            yield fqdn


def batch(host, query):
    url = 'http://{0}/range/list?{1}'.format(host, quote(query))
    request = Request(url, None, {'User-Agent': "salt" })
    try:
        with request_context(request) as response:
            code = response.getcode()
            if code != 200:
                raise RangeException("Got {0} response code from {1}".format(code, url))
            exception = response.info().getheader('RangeException')
            if exception:
                raise RangeException(exception)
            for line in response.readlines():
                yield line.rstrip()
    except URLError as exception:
        raise RangeException(exception)


