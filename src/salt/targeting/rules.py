'''

salt.targeting.rules
~~~~~~~~~~~~~~~~~~~~


'''

from abc import abstractmethod
from functools import wraps
from itertools import ifilter
import logging
log = logging.getLogger(__name__)

from salt.utils.matching import glob_match, pcre_match, pcre_compile, ipcidr_match

__all__ = [
    'Rule',
    'AllRule',
    'AnyRule',
    'NotRule',
    'GlobRule',
    'PCRERule',
    'GrainRule',
    'PillarRule',
    'GrainPCRERule',
    'SubnetIPRule',
    'ExselRule',
    'LocalStoreRule',
    'YahooRangeRule',
    'is_doubt',
]

class DoubtfulMinion(object):
    def __init__(self, minion, doubt=None):
        self.__dict__.update({
            'minion': minion,
            'doubt': doubt
        })

    def __getattr__(self, name):
        if name in self.__dict__.keys():
            return object.__getattr__(self, name)
        return getattr(self.minion, name)


def mark_doubt(minion):
    """Not enough information to know if we can pass this """
    if isinstance(minion, DoubtfulMinion):
        minion.doubt = True
    return minion

def clear_doubt(minion):
    if isinstance(minion, DoubtfulMinion):
        return minion.doubt == None
    return minion

def is_doubt(minion):
    if isinstance(minion, DoubtfulMinion):
        return minion.doubt == True


def rule_cmp(rule, other, *attrs):
    return isinstance(other, rule.__class__) \
       and all(getattr(rule, attr) == getattr(other, attr) for attr in attrs) \
       and Rule.__eq__(rule, other)

def rule_flatten(container, rules):
    merged = set()
    for rule in rules:
        if isinstance(rule, container.__class__):
            merged.update(rule_flatten(container, rule.rules))
        else:
            yield rule
    for rule in merged:
        yield rule

def rule_str(rule, *attrs):
    name = rule.__class__.__name__
    args = [repr(getattr(rule, attr)) for attr in attrs]
    return '{0}({1})'.format(name, ', '.join(args))

def force_set(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        response = func(*args, **kwargs)
        return set(response)
    return wrapped

class Rule(object):
    """
    Abstract class for rules.
    """

    #: used for sorting on heavy computations
    priority = None

    @abstractmethod
    def check(self, minions):
        """
        Optimistic check by master.
        """
        return minions

    @abstractmethod
    def match(self, minion):
        """
        Exact matching by minion.
        """
        return minion

    def __and__(self, other):
        return AllRule(self, other)

    def __or__(self, other):
        return AnyRule(self, other)

    def __neg__(self):
        return NotRule(self)

    def __eq__(self, other):
        return isinstance(other, self.__class__) \
           and self.priority == other.priority

    def __lt__(self, other):
        return isinstance(other, Rule) \
           and not self.priority > other.priority

class AllRule(Rule):
    priority = 70

    def __init__(self, *rules):
        self.rules = set(rule_flatten(self, rules))

    @force_set
    def check(self, minions):
        for rule in self:
            minions = rule.check(minions)
            if not minions:
                break
        return minions

    def match(self, minion):
        return all(minion for rule in self if rule.match(minion))

    def __and__(self, rule):
        self.rules.update(rule_flatten(self, [rule]))
        return self

    def __eq__(self, other):
        return rule_cmp(self, other, 'rules')

    def __iter__(self):
        """
        Iterate rules by priority.
        """
        for rule in sorted(self.rules):
            yield rule

    def __str__(self):
        """docstring for __str__"""
        name = self.__class__.__name__
        args = [str(rule) for rule in self.rules]
        return "{0}({1})".format(name, ', '.join(args))

class AnyRule(Rule):
    priority = 80

    def __init__(self, *rules):
        self.rules = set(rule_flatten(self, rules))

    @force_set
    def check(self, minions):
        if not minions:
            raise StopIteration

        remaining = set(minions)
        selected = set()
        for rule in self:
            try:
                found = rule.check(remaining)
                for minion in found:
                    yield minion
            except Exception as e:
                log.exception('Exception thrown %s . current rule %s', e, rule)
                raise e
            selected |= found
            remaining -= found
            if not remaining:
                raise StopIteration

    def match(self, minion):
        return any(minion for rule in self if rule.match(minion))

    def __or__(self, rule):
        self.rules.update(rule_flatten(self, [rule]))
        return self

    def __eq__(self, other):
        return rule_cmp(self, other, 'rules')

    def __iter__(self):
        """
        Iterate rules by priority.
        """
        for rule in sorted(self.rules):
            yield rule

    def __str__(self):
        """docstring for __str__"""
        name = self.__class__.__name__
        args = [str(rule) for rule in self.rules]
        return "{0}({1})".format(name, ', '.join(args))


class NotRule(Rule):
    def __init__(self, rule):
        self.rule = rule

    @force_set
    def check(self, minions):
        # do not discard doubtful minions
        # they don't always implements required attrs
        doubtful_minions = [DoubtfulMinion(minion) for minion in minions]
        found = self.rule.check(doubtful_minions)
        removable = set([d.minion for d in found if not d.doubt])
        return set(minions) - removable

    def match(self, minion):
        return not self.rule.match(minion)

    def __neg__(self):
        return self.rule

    def __eq__(self, other):
        return rule_cmp(self, other, 'rule')

    def __str__(self):
        """docstring for __str__"""
        name = self.__class__.__name__
        args = [str(self.rule)]
        return "{0}({1})".format(name, ', '.join(args))


class GlobRule(Rule):
    priority = 10

    def __init__(self, expr):
        self.expr = expr

    @force_set
    def check(self, minions):
        for minion in minions:
            if glob_match(self.expr, minion.id):
                yield minion

    def match(self, minion):
        return glob_match(self.expr, minion.id)

    def __eq__(self, other):
        return rule_cmp(self, other, 'expr')

    def __str__(self):
        return rule_str(self, 'expr')


class PCRERule(Rule):
    priority = 20

    def __init__(self, expr):
        self.expr = expr

    @force_set
    def check(self, minions):
        pattern = pcre_compile(self.expr)
        for minion in minions:
            if pattern.match(minion.id):
                yield minion

    def match(self, minion):
        pattern = pcre_compile(self.expr)
        return pattern.match(minion.id)

    def __eq__(self, other):
        return rule_cmp(self, other, 'expr')

    def __str__(self):
        return rule_str(self, 'expr')


class GrainRule(Rule):
    priority = 40

    def __init__(self, expr, delim):
        self.expr = expr
        self.delim = delim

    @force_set
    def check(self, minions):
        for minion in minions:
            if minion.grains is None:
                yield mark_doubt(minion)
            elif self.match(minion):
                yield minion

    def match(self, minion):
        if minion.grains is None:
            log.warning('grains are missing {0}'.format(minion.id))
            return False
        return glob_match(self.expr, minion.grains, self.delim)

    def __eq__(self, other):
        return rule_cmp(self, other, 'expr', 'delim')

    def __str__(self):
        return rule_str(self, 'expr', 'delim')


class PillarRule(Rule):
    priority = 40

    def __init__(self, expr, delim):
        self.expr = expr
        self.delim = delim

    @force_set
    def check(self, minions):
        for minion in minions:
            if minion.pillar is None:
                yield mark_doubt(minion)
            elif self.match(minion):
                yield minion

    def match(self, minion):
        if minion.pillar is None:
            log.warning('pillar is missing {0}'.format(minion.id))
            return False
        return glob_match(self.expr, minion.pillar, self.delim)

    def __eq__(self, other):
        return rule_cmp(self, other, 'expr', 'delim')

    def __str__(self):
        return rule_str(self, 'expr', 'delim')


class GrainPCRERule(Rule):
    priority = 40

    def __init__(self, expr, delim):
        self.expr = expr
        self.delim = delim

    @force_set
    def check(self, minions):
        for minion in minions:
            if minion.grains is None:
                yield mark_doubt(minion)
            elif self.match(minion):
                yield minion

    def match(self, minion):
        if minion.grains is None:
            log.warning('grains are missing {0}'.format(minion.id))
            return False
        return pcre_match(self.expr, minion.grains, self.delim)

    def __eq__(self, other):
        return rule_cmp(self, other, 'expr', 'delim')

    def __str__(self):
        return rule_str(self, 'expr', 'delim')


class SubnetIPRule(Rule):
    priority = 30

    def __init__(self, expr):
        self.expr = expr

    @force_set
    def check(self, minions):
        for minion in minions:
            if minion.ipv4 is None:
                yield mark_doubt(minion)
            elif self.match(minion):
                yield minion

    def match(self, minion):
        if minion.ipv4 is None:
            log.warning('ipv4 is missing {0}'.format(minion.id))
            return False
        return ipcidr_match(self.expr, minion.ipv4)

    def __eq__(self, other):
        return rule_cmp(self, other, 'expr')

    def __str__(self):
        return rule_str(self, 'expr')


class ExselRule(Rule):
    priority = 60

    def __init__(self, expr):
        self.expr = expr

    @force_set
    def check(self, minions):
        for minion in minions:
            if minion.functions is None:
                yield mark_doubt(minion)
            elif self.match(minion):
                yield minion

    def match(self, minion):
        if minion.functions is None:
            log.warning('functions is None {0}'.format(minion.id))
            return False
        if self.expr not in minion.functions:
            log.warning('functions is missing {0}'.format(minion.id))
            return False
        return bool(minion.functions[self.expr]())

    def __eq__(self, other):
        return rule_cmp(self, other, 'expr')

    def __str__(self):
        return rule_str(self, 'expr')


class LocalStoreRule(Rule):
    priority = 40

    def __init__(self, expr, delim):
        self.expr = expr
        self.delim = delim

    @force_set
    def check(self, minions):
        for minion in minions:
            if minion.data is None:
                yield mark_doubt(minion)
            elif self.match(minion):
                yield minion

    def match(self, minion):
        if minion.data is None:
            log.warning('data is None {0}'.format(minion.id))
            return False
        return glob_match(self.expr, minion.data, self.delim)

    def __eq__(self, other):
        return rule_cmp(self, other, 'expr', 'delim')

    def __str__(self):
        return rule_str(self, 'expr', 'delim')


class YahooRangeRule(Rule):
    """
    see https://github.com/ytoolshed/range
    https://github.com/grierj/range/wiki/Introduction-to-Range-with-YAML-files
    """
    priority = 50

    def __init__(self, expr, provider):
        self.expr = expr
        self.provider = provider

    @force_set
    def check(self, minions):
        remains = {}
        for minion in minions:
            if minion.fqdn is None:
                yield mark_doubt(minion)
            else:
                remains[minion.fqdn] = minion
        if remains:
            for host in self.provider.get(self.expr):
                if host in remains:
                    yield remains.pop(host)
                if not remains:
                    raise StopIteration

    def match(self, minion):
        if minion.fqdn is None:
            log.warning('fqdn is None {0}'.format(minion.id))
            return False

        return minion.fqdn in self.provider.get(self.expr)

    def __eq__(self, other):
        return rule_cmp(self, other, 'expr')

    def __str__(self):
        return rule_str(self, 'expr', 'provider')
