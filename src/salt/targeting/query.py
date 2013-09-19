'''

salt.targeting.query
~~~~~~~~~~~~~~~~~~~~


'''

import inspect
from salt.targeting import rules
from salt.targeting.parser import parse, normalize

import logging
log = logging.getLogger(__name__)

__all__ = [
    'Evaluator',
    'ListEvaluator',
    'RuleEvaluator',
    'NodeGroupEvaluator',
    'Query',
]

class Evaluator(object):
    """Base for evaluator classes"""


class ListEvaluator(Evaluator):
    """
    Converts comma separated value to AnyMatcher(default) matcher.
    """
    def __init__(self, parent):
        self.parent = parent

    def __call__(self, raw_value, opts):
        rule = opts.get('default_rule', rules.GlobRule)
        evaluator = RuleEvaluator(self.parent, rule)
        sub_rules = [
            evaluator(value, opts) for value in raw_value.split(',')
        ]

        return rules.AnyRule(*sub_rules)


class NodeGroupEvaluator(Evaluator):
    def __init__(self, parent):
        self.parent = parent

    def __call__(self, raw_value, opts):
        try:
            query = opts['macros'][raw_value]
            return self.parent.parse(query, **opts)
        except KeyError:
            raise Exception('node group {0} is not defined'.format(raw_value))


class RuleEvaluator(Evaluator):
    def __init__(self, parent, rule):
        self.parent = parent
        self.rule = rule
        self.arguments = ()

        arg_spec = inspect.getargspec(rule.__init__)
        if arg_spec.args:
            self.arguments = tuple(arg_spec.args[1:])
        self.varargs = arg_spec.varargs
        self.keywords = arg_spec.keywords

    def __call__(self, raw_value, opts):
        """
        raw_value is always the first value or Rule instance
        opts may contribute to the others.
        """
        args, kwargs = [], {}

        # if opts has self.varargs or self.keywords keys,
        # use them as default values for self.rule.
        if self.varargs and self.varargs in opts:
            args = opts[self.varargs]
            if not isinstance(args, (list, tuple)):
                raise ValueError('{0} is not iterable'.format(self.varargs))
        if self.keywords and self.keywords in opts:
            try:
                kwargs.update(opts[self.keywords])
            except ValueError as e:
                log.error('opts {0} must be a dict'.format(self.keywords))
                raise e

        for key in self.arguments:
            if key in opts:
                kwargs[key] = opts[key]
        # raw_value is always the 1st argument
        kwargs[self.arguments[0]] = raw_value

        try:
            return self.rule(*args, **kwargs)
        except TypeError as e:
            log.debug('fail: class={0}({1}, *args={2}, **kwargs={3})'.format(
                self.rule.__name__,
                repr(raw_value),
                repr(args),
                repr(kwargs),
            ))
            raise e


def make_evaluator(obj, query):
    try:
        if issubclass(obj, rules.Rule):
            return RuleEvaluator(query, obj)
        if issubclass(obj, Evaluator):
            return obj(query)
    except TypeError:
        pass

    raise Exception('Must be rules.Rule or a targeting.Evaluator class', obj)


class Query(object):
    def __init__(self, default_rule, **opts):
        self.registry = {}
        self.evaluators = {}
        self.opts = {
            'default_rule': default_rule,
            'delim': ':',
            'macros': {},
        }
        self.opts.update(opts)

    def register(self, obj, prefix=None, passthru=None):
        if prefix and prefix in self.registry:
            raise ValueError('Prefix already registered')
        if passthru:
            funcname = 'parse_' + passthru
            if hasattr(self, funcname):
                raise AttributeError(
                    "{0} object already has attribute {1}".format(
                        repr(self.__class__.__name__), funcname))

        evaluator = make_evaluator(obj, self)

        if passthru:
            def curried_func(query, **opts):
                try:
                    parser_opts = self.opts.copy()
                    parser_opts.update(opts)
                    return evaluator(normalize(query), parser_opts)
                except TypeError as e:
                    log.debug('fail: evaluator={0}, class_params={1}, func_params={2}'.format(
                        evaluator.__class__.__name__,
                        repr(self.opts),
                        repr(opts)
                    ))
                    raise e
            curried_func.__name__ = funcname
            curried_func.__doc__ = "Shortcut for {0}".format(prefix)
            setattr(self, funcname, curried_func)

        if prefix:
            self.evaluators[prefix] = evaluator
            self.registry[prefix] = obj

    def parse(self, query, **opts):
        parser_opts = self.opts.copy()
        if opts:
            parser_opts.update(opts)
        default_evaluator = RuleEvaluator(self, parser_opts['default_rule'])
        def parse_rule(value):
            prefix, sep, raw_value = value.partition('@')
            if prefix and raw_value and prefix in self.evaluators:
                return self.evaluators[prefix](raw_value, parser_opts)
            return default_evaluator(value, parser_opts)

        return parse(query, parse_rule)

    parse_compound = parse

    def querify(self, obj, **opts):
        parser_opts = self.opts.copy()
        if opts:
            parser_opts.update(opts)
        def parenthize(objs):
            for obj in objs:
                if isinstance(obj, (rules.AnyRule, rules.AllRule)):
                    yield '({0})'.format(self.querify(obj))
                else:
                    yield self.querify(obj)

        if isinstance(obj, rules.NotRule):
            return 'not ' + ''.join(parenthize([obj.rule]))
        if isinstance(obj, rules.AnyRule):
            return ' or '.join(parenthize(obj.__iter__()))
        if isinstance(obj, rules.AllRule):
            return ' and '.join(parenthize(obj.__iter__()))
        if isinstance(obj, parser_opts['default_rule']):
            return obj.expr
        for prefix, base in self.registry.items():
            if isinstance(obj, base):
                return prefix + '@' + obj.expr
        raise Exception('Not defined for {0}'.format(repr(obj.__class__.__name__)))
