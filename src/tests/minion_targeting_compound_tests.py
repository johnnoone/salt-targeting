try:
    import unittest2 as unittest
except ImportError:
    import unittest

from salt.targeting import *

class MinionMock(object):
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class MinionTargetingTestCase(unittest.TestCase):
    def test_glob(self):
        matcher = minion_targeting.parse('web*')
        minion = MinionMock(id='web*')
        assert matcher.match(minion)
        assert minion_targeting.querify(matcher) == 'web*'
        assert isinstance(matcher, GlobRule)

    def test_grain(self):
        matcher = minion_targeting.parse('G@os:Ubuntu')
        minion = MinionMock(grains={"os": "Ubuntu"})
        assert matcher.match(minion)
        assert minion_targeting.querify(matcher) == 'G@os:Ubuntu'
        assert isinstance(matcher, GrainRule)

    def test_grain_pcre(self):
        matcher = minion_targeting.parse('P@role:(web|back)\w+')
        minion = MinionMock(grains={"role": ["weblol"]})
        assert matcher.match(minion)
        assert minion_targeting.querify(matcher) == 'P@role:(web|back)\w+'
        assert isinstance(matcher, GrainPCRERule)

    def test_list(self):
        matcher = minion_targeting.parse('L@foo,bar,baz*')
        minion = MinionMock(id="bazinga")
        assert matcher.match(minion)
        assert isinstance(matcher, AnyRule)

    def test_pillar(self):
        matcher = minion_targeting.parse('I@foo:bar')
        minion = MinionMock(pillar={'foo': ['bar']})
        assert matcher.match(minion)
        assert minion_targeting.querify(matcher) == 'I@foo:bar'
        assert isinstance(matcher, PillarRule)

    def test_pcre(self):
        matcher = minion_targeting.parse('E@ic-(foo|bar)\w+')
        minion = MinionMock(id="ic-foojistoo")
        assert matcher.match(minion)
        assert minion_targeting.querify(matcher) == 'E@ic-(foo|bar)\w+'
        assert isinstance(matcher, PCRERule)

    def test_subnet_ip(self):
        matcher = minion_targeting.parse('S@192.168.1.0/24')
        minion = MinionMock(ipv4=["192.168.1.0"])
        assert matcher.match(minion)
        assert minion_targeting.querify(matcher) == 'S@192.168.1.0/24'
        assert isinstance(matcher, SubnetIPRule)

    def test_all_simple_minion_targeting(self):
        matcher = minion_targeting.parse('foo and G@bar:baz')
        minion = MinionMock(id="foo", grains={'bar':'baz'})
        assert matcher.match(minion)
        assert isinstance(matcher, AllRule)

    def test_or_simple_minion_targeting(self):
        matcher = minion_targeting.parse('foo or G@bar:baz')
        minion = MinionMock(id="foo", grains={'bar':'foo'})
        assert matcher.match(minion)
        assert isinstance(matcher, AnyRule)

    def test_not_simple_minion_targeting(self):
        matcher = minion_targeting.parse('not (G@bar:baz or toto)')
        minion = MinionMock(id="foo", grains={'bar':'bazinga'})
        assert matcher.match(minion)
        assert isinstance(matcher, NotRule)

    def test_complex_minion_targeting(self):
        matcher = minion_targeting.parse('not (G@bar:baz and not toto) or not I@foo:bar:baz')
        minion = MinionMock(id="foo", grains={'bar':'foo'}, pillar=None)
        assert matcher.match(minion)

    def test_macros(self):
        matcher = minion_targeting.parse('G@bar:baz or not N@foo', macros={
            'foo': 'bar'
        })
        minion = MinionMock(id="foo", grains={'bar':'foo'})
        assert matcher.match(minion)
        assert isinstance(matcher, AnyRule)
