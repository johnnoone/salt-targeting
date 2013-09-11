'''

salt.targeting
~~~~~~~~~~~~~~


'''

import logging
log = logging.getLogger(__name__)

from .parser import *
from .query import *
from .rules import *


class MinionBase(object):
    attrs = ('id', 'fqdn', 'ipv4', 'grains', 'pillar', 'data', 'functions')

    def __init__(self, **kwargs):
        for attr in self.attrs:
            setattr(self, attr, kwargs.pop(attr, None))
        if kwargs:
            raise ValueError('Illegal values: {0}'.format(repr(kwargs)))

class CheckableMinion(MinionBase): pass

class MatchableMinion(MinionBase): pass


class CheckMinions(object):
    def __init__(self, opts):
        self.opts = opts
        self.serial = salt.payload.Serial(opts)

    @property
    def minions(self):
        '''
        Return a list of all minions that have auth'd
        '''
        minions = os.listdir(os.path.join(self.opts['pki_dir'], 'minions'))
        return [MatchableMinion(id=minion) for minion in minions]

    def check_glob(self, expr):
        # delim = __opts__.get('matcher_delim', ':')
        return GlobRule(expr).check(self.minions)

    def check_pcre(self, expr):
        # delim = __opts__.get('matcher_delim', ':')
        return PCRERule(expr).check(self.minions)

    def check_list(self, expr):
        # delim = __opts__.get('matcher_delim', ':')
        return compound.evaluators['L'](expr, {}).check(self.minions)

    def check_grain(self, expr):
        return GrainRule(expr, delim).check(self.minions)

    def check_grain_pcre(self, expr):
        return GrainPCRERule(expr, delim).check(self.minions)

    def check_minions(self, expr, expr_form='glob'):
        '''
        Check the passed regex against the available minions' public keys
        stored for authentication. This should return a set of ids which
        match the regex, this will then be used to parse the returns to
        make sure everyone has checked back in.
        '''
        try:
            minions = {'glob': self.check_glob,
                       'pcre': self.check_pcre,
                       'list': self.check_list,
                       'grain': self.check_grain,
                       'grain_pcre': self.check_grain_pcre,
                       'exsel': self.check_exsel,
                       'pillar': self.check_pillar,
                       'compound': self.check_compound,
                      }[expr_form](expr)
        except Exception:
            log.exception(('Failed matching available minions with {0} pattern: {1}'
                           ).format(expr_form, expr))
            minions = expr
        return minions


class MatchMinion(object):
    pass

def master_check(query, minions, opts):
    delim = __opts__.get('matcher_delim', ':')
    range_provider = __opts__.get('range_provider', None)
    matcher = compound.parse(query, delim=None, range_provider=None)

def minion_match(query, minion, opts):
    delim = __opts__.get('matcher_delim', ':')
    range_provider = __opts__.get('range_provider', None)
    matcher = compound.parse(query, delim=None, range_provider=None)
