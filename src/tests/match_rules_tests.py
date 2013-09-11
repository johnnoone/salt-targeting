try:
    import unittest2 as unittest
except ImportError:
    import unittest

from salt.targeting.rules import *


class MinionMock(object):
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class MatchRulesTestCase(unittest.TestCase):
    def test_inheritance(self):
        m = GrainRule('foo:bar', ':')
        n = -m

        assert isinstance(m, GrainRule)
        assert not isinstance(m, NotRule)
        assert not isinstance(n, GrainRule)
        assert isinstance(n, NotRule)

        assert issubclass(GrainRule, Rule)
        assert issubclass(NotRule, Rule)
        assert not issubclass(GrainRule, NotRule)
        assert not issubclass(NotRule, GrainRule)

    def test_grain_matcher(self):
        matcher = GrainRule('os:Ubuntu', ':')
        assert "GrainRule('os:Ubuntu', ':')" == str(matcher)
        assert matcher == eval(str(matcher))

        minion = MinionMock(grains={'os': 'Ubuntu'})
        assert matcher.match(minion)
        assert not (- matcher).match(minion)

    def test_grain_pillar(self):
        matcher = PillarRule('user:admin', ':')
        assert "PillarRule('user:admin', ':')" == str(matcher)
        assert matcher == eval(str(matcher))

        minion = MinionMock(pillar={'user': 'root'})
        assert not matcher.match(minion)
        assert (- matcher).match(minion)

    def test_compound_matcher(self):
        g = GrainRule('os:Ubuntu', ':')
        h = PillarRule('user:adm:toto', ':')
        i = GlobRule('127.0.**')
        j = PCRERule('.*admin')

        k = g | i & -h | j

        minion = MinionMock(id="127.0.-testadmin", grains={'os': 'Ubuntu'}, pillar=None)

        assert g.match(minion)
        assert not h.match(minion)
        assert (- h).match(minion)
        assert i.match(minion)
        assert j.match(minion)
        assert k.match(minion)


        # TODO
        # __str__ must represent a compound query
        # print k

        # __repr__ must return an evaluable python string
        evaluated = eval(str(k))
        assert isinstance(evaluated, AnyRule)

    def test_exsel(self):
        matcher = ExselRule('foo.bar')
        assert "ExselRule('foo.bar')" == str(matcher)
        assert matcher == eval(str(matcher))

        minion = MinionMock(functions={'foo.bar': lambda: True})
        assert matcher.match(minion)
        assert not (- matcher).match(minion)

    def test_local_store(self):
        matcher = LocalStoreRule('foo:bar', ':')
        assert "LocalStoreRule('foo:bar', ':')" == str(matcher)
        assert matcher == eval(str(matcher))

        minion = MinionMock(data={"foo": "bar"})
        assert matcher.match(minion)
        assert not (- matcher).match(minion)

    def test_yahoo_range(self):
        server = {'%foo': ['bar.example.com']}
        matcher = YahooRangeRule('%foo', server)
        assert "YahooRangeRule('%foo', {0})".format(repr(server)) == str(matcher)
        assert matcher == eval(str(matcher))

        minion = MinionMock(fqdn="bar.example.com")
        assert matcher.match(minion)
        assert not (- matcher).match(minion)