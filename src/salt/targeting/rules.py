'''

salt.targeting.rules
~~~~~~~~~~~~~~~~~~~~


'''

from abc import abstractmethod
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
]

class Doubtful(object):
    def __init__(self, obj, doubt=None):
        self.__dict__.update({
            'obj': obj,
            'doubt': doubt
        })

    def __getattr__(self, name):
        if name in self.__dict__.keys():
            return object.__getattr__(self, name)
        return getattr(self.obj, name)


def mark_doubt(obj):
    """Match methods may return a misguidance"""
    if hasattr(obj, 'doubt'):
        obj.doubt = True
    return obj


def is_deceipt(obj):
    return getattr(obj, 'doubt', False)


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


class Rule(object):
    """
    Abstract class for rules.

    .. todo:: force __init__ to have at least 1 non-default args
    """

    #: used for sorting in order to avoid doing some heavy computations
    priority = None

    def check(self, objs):
        """
        Optimistic check by master.
        """
        results = self.filter(objs)
        return set(results)

    @abstractmethod
    def filter(self, objs):
        return objs

    @abstractmethod
    def match(self, obj):
        """
        Exact matching by obj.
        """
        return obj

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
        """
        Ordering is 10, 20, 30 ... None.
        """
        if self.priority is None:
            return False
        if isinstance(other, Rule):
            if other.priority is None:
                return True
            return self.priority <= other.priority
        return True


class AllRule(Rule):
    priority = 70

    def __init__(self, *rules):
        self.rules = set(rule_flatten(self, rules))

    def filter(self, objs):
        for rule in self:
            results, objs = rule.filter(objs), set()
            for obj in results:
                if is_deceipt(obj):
                    yield obj
                else:
                    objs.add(obj)
            if not objs:
                raise StopIteration
        for obj in objs:
            yield obj

    def match(self, obj):
        return all(obj for rule in self if rule.match(obj))

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
        name = self.__class__.__name__
        args = [str(rule) for rule in self.rules]
        return "{0}({1})".format(name, ', '.join(args))

class AnyRule(Rule):
    priority = 80

    def __init__(self, *rules):
        self.rules = set(rule_flatten(self, rules))

    def filter(self, objs):
        if not objs:
            raise StopIteration

        remaining = set(objs)
        for rule in self:
            try:
                found = rule.filter(remaining)
                for obj in found:
                    yield obj
            except Exception as e:
                log.exception('Exception thrown %s . current rule %s', e, rule)
                raise e
            remaining -= set(found)
            if not remaining:
                raise StopIteration

    def match(self, obj):
        return any(obj for rule in self if rule.match(obj))

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
        name = self.__class__.__name__
        args = [str(rule) for rule in self.rules]
        return "{0}({1})".format(name, ', '.join(args))


class NotRule(Rule):
    def __init__(self, rule):
        self.rule = rule

    def filter(self, objs):
        # do not discard misleading objs
        # they don't always implements required attrs
        doubtful_objs = [Doubtful(obj) for obj in objs]
        found = self.rule.filter(doubtful_objs)
        removable = set([d.obj for d in found if not d.doubt])
        return set(objs) - removable

    def match(self, obj):
        return not self.rule.match(obj)

    def __neg__(self):
        return self.rule

    def __eq__(self, other):
        return rule_cmp(self, other, 'rule')

    def __str__(self):
        name = self.__class__.__name__
        args = [str(self.rule)]
        return "{0}({1})".format(name, ', '.join(args))


class GlobRule(Rule):
    priority = 10

    def __init__(self, expr):
        self.expr = expr

    def filter(self, objs):
        for obj in objs:
            if glob_match(self.expr, obj.id):
                yield obj

    def match(self, obj):
        return glob_match(self.expr, obj.id)

    def __eq__(self, other):
        return rule_cmp(self, other, 'expr')

    def __str__(self):
        return rule_str(self, 'expr')


class PCRERule(Rule):
    priority = 20

    def __init__(self, expr):
        self.expr = expr

    def filter(self, objs):
        pattern = pcre_compile(self.expr)
        for obj in objs:
            if pattern.match(obj.id):
                yield obj

    def match(self, obj):
        pattern = pcre_compile(self.expr)
        return pattern.match(obj.id)

    def __eq__(self, other):
        return rule_cmp(self, other, 'expr')

    def __str__(self):
        return rule_str(self, 'expr')


class GrainRule(Rule):
    priority = 40

    def __init__(self, expr, delim):
        self.expr = expr
        self.delim = delim

    def filter(self, objs):
        for obj in objs:
            if obj.grains is None:
                yield mark_doubt(obj)
            elif self.match(obj):
                yield obj

    def match(self, obj):
        if obj.grains is None:
            log.warning('grains are missing {0}'.format(obj.id))
            return False
        return glob_match(self.expr, obj.grains, self.delim)

    def __eq__(self, other):
        return rule_cmp(self, other, 'expr', 'delim')

    def __str__(self):
        return rule_str(self, 'expr', 'delim')


class PillarRule(Rule):
    priority = 40

    def __init__(self, expr, delim):
        self.expr = expr
        self.delim = delim

    def filter(self, objs):
        for obj in objs:
            if obj.pillar is None:
                yield mark_doubt(obj)
            elif self.match(obj):
                yield obj

    def match(self, obj):
        if obj.pillar is None:
            log.warning('pillar is missing {0}'.format(obj.id))
            return False
        return glob_match(self.expr, obj.pillar, self.delim)

    def __eq__(self, other):
        return rule_cmp(self, other, 'expr', 'delim')

    def __str__(self):
        return rule_str(self, 'expr', 'delim')


class GrainPCRERule(Rule):
    priority = 40

    def __init__(self, expr, delim):
        self.expr = expr
        self.delim = delim

    def filter(self, objs):
        for obj in objs:
            if obj.grains is None:
                yield mark_doubt(obj)
            elif self.match(obj):
                yield obj

    def match(self, obj):
        if obj.grains is None:
            log.warning('grains are missing {0}'.format(obj.id))
            return False
        return pcre_match(self.expr, obj.grains, self.delim)

    def __eq__(self, other):
        return rule_cmp(self, other, 'expr', 'delim')

    def __str__(self):
        return rule_str(self, 'expr', 'delim')


class SubnetIPRule(Rule):
    priority = 30

    def __init__(self, expr):
        self.expr = expr

    def filter(self, objs):
        for obj in objs:
            if obj.ipv4 is None:
                yield mark_doubt(obj)
            elif self.match(obj):
                yield obj

    def match(self, obj):
        if obj.ipv4 is None:
            log.warning('ipv4 is missing {0}'.format(obj.id))
            return False
        return ipcidr_match(self.expr, obj.ipv4)

    def __eq__(self, other):
        return rule_cmp(self, other, 'expr')

    def __str__(self):
        return rule_str(self, 'expr')


class ExselRule(Rule):
    priority = 60

    def __init__(self, expr):
        self.expr = expr

    def filter(self, objs):
        for obj in objs:
            if obj.functions is None:
                yield mark_doubt(obj)
            elif self.match(obj):
                yield obj

    def match(self, obj):
        if obj.functions is None:
            log.warning('functions is None {0}'.format(obj.id))
            return False
        if self.expr not in obj.functions:
            log.warning('functions is missing {0}'.format(obj.id))
            return False
        return bool(obj.functions[self.expr]())

    def __eq__(self, other):
        return rule_cmp(self, other, 'expr')

    def __str__(self):
        return rule_str(self, 'expr')


class LocalStoreRule(Rule):
    priority = 40

    def __init__(self, expr, delim):
        self.expr = expr
        self.delim = delim

    def filter(self, objs):
        for obj in objs:
            if obj.data is None:
                yield mark_doubt(obj)
            elif self.match(obj):
                yield obj

    def match(self, obj):
        if obj.data is None:
            log.warning('data is None {0}'.format(obj.id))
            return False
        return glob_match(self.expr, obj.data, self.delim)

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

    def filter(self, objs):
        remains = {}
        for obj in objs:
            if obj.fqdn is None:
                yield mark_doubt(obj)
            else:
                remains[obj.fqdn] = obj
        if remains:
            for host in self.provider.get(self.expr):
                if host in remains:
                    yield remains.pop(host)
                if not remains:
                    raise StopIteration

    def match(self, obj):
        if obj.fqdn is None:
            log.warning('fqdn is None {0}'.format(obj.id))
            return False

        return obj.fqdn in self.provider.get(self.expr)

    def __eq__(self, other):
        return rule_cmp(self, other, 'expr')

    def __str__(self):
        return rule_str(self, 'expr', 'provider')
