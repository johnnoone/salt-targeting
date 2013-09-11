try:
    import unittest2 as unittest
except ImportError:
    import unittest

from salt.targeting.rules import *


class MinionMock(object):
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.kwargs = kwargs

    def __str__(self):
        args = []
        for k, v in self.kwargs.items():
            args.append(k + '='+ repr(v))
        args.append('is_doubt=' + repr(is_doubt(self)))
        return "MinionMock({0})".format(', '.join(args))
    __repr__ = __str__

class CheckRulesTestCase(unittest.TestCase):
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

        minion_a = MinionMock(grains={'os': 'Ubuntu'})
        minion_b = MinionMock(grains=None)
        minion_c = MinionMock(grains={'os': 'Redhat'})
        minions = [minion_a, minion_b, minion_c]
        checked = matcher.check(minions)
        assert minion_a in checked
        assert minion_b in checked
        assert minion_c not in checked

    def test_grain_pillar(self):
        matcher = PillarRule('user:admin', ':')
        assert "PillarRule('user:admin', ':')" == str(matcher)
        assert matcher == eval(str(matcher))

        minion_a = MinionMock(pillar={'user': 'admin'})
        minion_b = MinionMock(pillar=None)
        minion_c = MinionMock(pillar={'user': 'other'})
        minions = [minion_a, minion_b, minion_c]
        checked = matcher.check(minions)
        assert minion_a in checked
        assert minion_b in checked
        assert minion_c not in checked

    def test_compound_matcher(self):
        g = GrainRule('os:Ubuntu', ':')
        h = PillarRule('user:adm:toto', ':')
        i = GlobRule('127.0.**')
        j = PCRERule('.*admin')

        k = g | i & -h | j

        minion_a = MinionMock(id="127.0.-testadmin", grains={'os': 'Ubuntu'}, pillar={})
        minion_b = MinionMock(id="127.0.12.21", grains=None, pillar=None)
        minion_c = MinionMock(id="245.0.12.21", grains={'os': 'Redhat'}, pillar={'user:adm': 'toto'})
        minions = [minion_a, minion_b, minion_c]

        checked = g.check(minions)
        assert minion_a in checked
        assert minion_b in checked
        assert minion_c not in checked

        checked = h.check(minions)
        assert minion_a not in checked
        assert minion_b in checked
        assert minion_c in checked, checked

        checked = (- h).check(minions)
        assert minion_a in checked
        assert minion_b in checked
        assert minion_c not in checked

        checked = i.check(minions)
        assert minion_a in checked
        assert minion_b in checked
        assert minion_c not in checked

        checked = j.check(minions)
        assert minion_a in checked
        assert minion_b not in checked
        assert minion_c not in checked

        checked = k.check(minions)
        assert minion_a in checked
        assert minion_b in checked
        assert minion_c not in checked

        # __repr__ must return an evaluable python string
        evaluated = eval(str(k))
        assert isinstance(evaluated, AnyRule)

    def test_exsel(self):
        matcher = ExselRule('foo.bar')
        assert "ExselRule('foo.bar')" == str(matcher)
        assert matcher == eval(str(matcher))

        minion_a = MinionMock(id="a", functions={'foo.bar': lambda: True})
        minion_b = MinionMock(id="b", functions=None)
        minion_c = MinionMock(id="c", functions={})
        minions = [minion_a, minion_b, minion_c]

        checked = matcher.check(minions)
        assert minion_a in checked
        assert minion_b in checked
        assert minion_c not in checked

        checked = (- matcher).check(minions)
        assert minion_a not in checked
        assert minion_b in checked
        assert minion_c in checked

    def test_local_store(self):
        matcher = LocalStoreRule('foo:bar', ':')
        assert "LocalStoreRule('foo:bar', ':')" == str(matcher)
        assert matcher == eval(str(matcher))

        minion_a = MinionMock(data={"foo": "bar"})
        minion_b = MinionMock(data=None)
        minion_c = MinionMock(data={})
        minions = [minion_a, minion_b, minion_c]

        checked = matcher.check(minions)
        assert minion_a in checked
        assert minion_b in checked
        assert minion_c not in checked

        checked = (- matcher).check(minions)
        assert minion_a not in checked
        assert minion_b in checked
        assert minion_c in checked

    def test_yahoo_range(self):
        server = {'%foo': ['bar.example.com']}
        matcher = YahooRangeRule('%foo', server)
        assert "YahooRangeRule('%foo', {0})".format(repr(server)) == str(matcher)
        assert matcher == eval(str(matcher))

        minion_a = MinionMock(fqdn="bar.example.com")
        minion_b = MinionMock(fqdn=None)
        minion_c = MinionMock(fqdn="saltstack.com")
        minions = [minion_a, minion_b, minion_c]

        checked = matcher.check(minions)
        assert minion_a in checked
        assert minion_b in checked
        assert minion_c not in checked

        checked = (- matcher).check(minions)
        assert minion_a not in checked
        assert minion_b in checked
        assert minion_c in checked
