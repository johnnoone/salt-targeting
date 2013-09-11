try:
    import unittest2 as unittest
except ImportError:
    import unittest

from salt.targeting.rules import *
from salt.targeting.query import *

class MinionMock(object):
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class ParserTestCase(unittest.TestCase):
    def test_glob(self):
        matcher = compound.parse('web*')
        minion = MinionMock(id='web*')
        assert matcher.match(minion)
        assert compound.querify(matcher) == 'web*'
        assert isinstance(matcher, GlobRule)

    def test_grain(self):
        matcher = compound.parse('G@os:Ubuntu')
        minion = MinionMock(grains={"os": "Ubuntu"})
        assert matcher.match(minion)
        assert compound.querify(matcher) == 'G@os:Ubuntu'
        assert isinstance(matcher, GrainRule)

    def test_grain_pcre(self):
        matcher = compound.parse('P@role:(web|back)\w+')
        minion = MinionMock(grains={"role": ["weblol"]})
        assert matcher.match(minion)
        assert compound.querify(matcher) == 'P@role:(web|back)\w+'
        assert isinstance(matcher, GrainPCRERule)

    def test_list(self):
        matcher = compound.parse('L@foo,bar,baz*')
        minion = MinionMock(id="bazinga")
        assert matcher.match(minion)
        assert isinstance(matcher, AnyRule)

    def test_pillar(self):
        matcher = compound.parse('I@foo:bar')
        minion = MinionMock(pillar={'foo': ['bar']})
        assert matcher.match(minion)
        assert compound.querify(matcher) == 'I@foo:bar'
        assert isinstance(matcher, PillarRule)

    def test_pcre(self):
        matcher = compound.parse('E@ic-(foo|bar)\w+')
        minion = MinionMock(id="ic-foojistoo")
        assert matcher.match(minion)
        assert compound.querify(matcher) == 'E@ic-(foo|bar)\w+'
        assert isinstance(matcher, PCRERule)

    def test_subnet_ip(self):
        matcher = compound.parse('S@192.168.1.0/24')
        minion = MinionMock(ipv4=["192.168.1.0"])
        assert matcher.match(minion)
        assert compound.querify(matcher) == 'S@192.168.1.0/24'
        assert isinstance(matcher, SubnetIPRule)

    def test_all_simple_compound(self):
        matcher = compound.parse('foo and G@bar:baz')
        minion = MinionMock(id="foo", grains={'bar':'baz'})
        assert matcher.match(minion)
        assert isinstance(matcher, AllRule)

    def test_or_simple_compound(self):
        matcher = compound.parse('foo or G@bar:baz')
        minion = MinionMock(id="foo", grains={'bar':'foo'})
        assert matcher.match(minion)
        assert isinstance(matcher, AnyRule)

    def test_not_simple_compound(self):
        matcher = compound.parse('not (G@bar:baz or toto)')
        minion = MinionMock(id="foo", grains={'bar':'bazinga'})
        assert matcher.match(minion)
        assert isinstance(matcher, NotRule)

    def test_complex_compound(self):
        matcher = compound.parse('not (G@bar:baz and not toto) or not I@foo:bar:baz')
        minion = MinionMock(id="foo", grains={'bar':'foo'}, pillar=None)
        assert matcher.match(minion)

    def test_macros(self):
        matcher = compound.parse('G@bar:baz or not N@foo', macros={
            'foo': 'bar'
        })
        minion = MinionMock(id="foo", grains={'bar':'foo'})
        assert matcher.match(minion)
        assert isinstance(matcher, AnyRule)
