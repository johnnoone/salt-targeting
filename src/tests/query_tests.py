try:
    import unittest2 as unittest
except ImportError:
    import unittest

from salt.targeting.query import *
from salt.targeting import rules


class QueryTestCase(unittest.TestCase):
    def test_glob(self):
        matcher = compound.parse_glob('foo and bar')
        assert isinstance(matcher, rules.GlobRule)

    def test_grain(self):
        matcher = compound.parse_grain('foo and bar')
        assert isinstance(matcher, rules.GrainRule)

    def test_pillar(self):
        matcher = compound.parse_pillar('foo and bar')
        assert isinstance(matcher, rules.PillarRule)
