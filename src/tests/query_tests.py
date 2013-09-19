try:
    import unittest2 as unittest
except ImportError:
    import unittest

from salt.targeting import *


class QueryTestCase(unittest.TestCase):
    def test_glob(self):
        matcher = minion_targeting.parse_glob('foo and bar')
        assert isinstance(matcher, GlobRule)

    def test_grain(self):
        matcher = minion_targeting.parse_grain('foo and bar')
        assert isinstance(matcher, GrainRule)

    def test_pillar(self):
        matcher = minion_targeting.parse_pillar('foo and bar')
        assert isinstance(matcher, PillarRule)

    def test_escape(self):
        matcher = minion_targeting.parse('G@foo_bar or (*.test) and baz')
        assert isinstance(matcher, AnyRule)
        assert len(matcher.rules) == 2

        matcher = minion_targeting.parse('G@foo bar or (*.test) and baz')
        assert isinstance(matcher, AnyRule)
        assert len(matcher.rules) == 2

        matcher = minion_targeting.parse('G@foo bar or (*.test lol) and baz')
        assert isinstance(matcher, AnyRule)
        assert len(matcher.rules) == 2

        matcher = minion_targeting.parse('G@foo bar or (*.test or lol) and baz')
        assert isinstance(matcher, AnyRule)
        assert len(matcher.rules) == 2

        matcher = minion_targeting.parse('G@foo bar and (*.test or lol) or baz')
        assert isinstance(matcher, AnyRule)
        assert len(matcher.rules) == 2

        matcher = minion_targeting.parse('*.example.com and not (I@fullname:John Doe or D@role:web)')
        assert isinstance(matcher, AllRule)
        assert len(matcher.rules) == 2

        matcher = minion_targeting.parse('G@foo:   bar baz)  ')
        resp1 = minion_targeting.querify(matcher)

        matcher = minion_targeting.parse_grain('foo:   bar baz)  ')
        resp2 = minion_targeting.querify(matcher)
        assert resp1 == resp2 == 'G@foo: bar baz)'

        with self.assertRaises(SyntaxError):
            matcher = minion_targeting.parse('G@foo:   bar baz) and ')
