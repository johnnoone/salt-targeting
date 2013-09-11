'''

salt.targeting.query
~~~~~~~~~~~~~~~~~~~~


'''

import inspect
from salt.targeting import rules
from salt.targeting.parser import parse
from functools import partial

import logging
log = logging.getLogger(__name__)

__all__ = [
    'Evaluator',
    'ListEvaluator',
    'RuleEvaluator',
    'NodeGroupEvaluator',
    'Query',
    'compound',
]

class Evaluator(object):
    """Base for evaluator classes"""


class ListEvaluator(Evaluator):
    def __init__(self, parent):
        self.parent = parent

    def __call__(self, raw_value, parameters):
        rule = parameters.get('default_rule', rules.GlobRule)
        evaluator = RuleEvaluator(self.parent, rule)
        sub_rules = [
            evaluator(value, parameters) for value in raw_value.split(',')
        ]

        return rules.AnyRule(*sub_rules)


class NodeGroupEvaluator(Evaluator):
    def __init__(self, parent):
        self.parent = parent

    def __call__(self, raw_value, parameters):
        try:
            query = parameters['macros'][raw_value]
            return self.parent.parse(query, **parameters)
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

        log.debug('rule {0} args = {0}, varargs=, keywords='.format(self.arguments))


    def __call__(self, raw_value, parameters):
        """
        raw_value is always the first value or Rule instance
        parameters may contribute to the others.
        """
        args, kwargs = [], {}
        for key, value in parameters.items():
            if key in self.arguments:
                kwargs[key] = value
        if self.keywords and self.keywords in parameters:
            kwargs[self.keywords] = parameters[self.keywords]
        if self.varargs and self.varargs in parameters:
            args = parameters[self.varargs]
            if not isinstance(args, (list, tuple)):
                raise ValueError('{0} is not iterable'.format(self.varargs))
        try:
            return self.rule(raw_value, *args, **kwargs)
        except TypeError as e:
            log.debug('fail: class={0}({1}, *args={2}, **kwargs={3})'.format(
                self.rule.__name__,
                repr(raw_value),
                repr(args),
                repr(kwargs),
            ))
            raise e

def make_evaluator(obj, targeting):
    try:
        if issubclass(obj, rules.Rule):
            return RuleEvaluator(targeting, obj)
        if issubclass(obj, Evaluator):
            return obj(targeting)
    except TypeError:
        pass

    raise Exception('Must be rules.Rule or a targeting.Evaluator class', obj)


class Query(object):
    def __init__(self, default_rule=None, **parameters):
        self.registry = {}
        self.evaluators = {}
        self.parameters = {
            'default_rule': default_rule or rules.GlobRule,
            'delim': ':',
            'macros': {},
        }
        self.parameters.update(parameters)

    def register(self, prefix, obj, shortcut=None):
        if prefix and prefix in self.registry:
            raise ValueError('Prefix already registered')
        if shortcut:
            funcname = 'parse_' + shortcut
            if hasattr(self, 'funcname'):
                raise AttributeError(
                    "{0} object already has attribute {1}".format(
                        repr(self.__class__.__name__), funcname))

        evaluator = make_evaluator(obj, self)

        if shortcut:
            def curried_func(query, **parameters):
                try:
                    parser_parameters = self.parameters.copy()
                    parser_parameters.update(parameters)
                    return evaluator(query, parser_parameters)
                except TypeError as e:
                    log.debug('fail: evaluator={0}, class_params={1}, func_params={2}'.format(
                        evaluator.__class__.__name__,
                        repr(self.parameters),
                        repr(parameters)
                    ))
                    raise e
            curried_func.__name__ = funcname
            curried_func.__doc__ = "Shortcut for {0}".format(prefix)
            setattr(self, funcname, curried_func)

        if prefix:
            self.evaluators[prefix] = evaluator
            self.registry[prefix] = obj

    def parse(self, query, **parameters):
        parser_parameters = self.parameters.copy()
        if parameters:
            parser_parameters.update(parameters)
        default_evaluator = RuleEvaluator(self, parser_parameters['default_rule'])
        def parse_rule(value):
            prefix, sep, raw_value = value.partition('@')
            if prefix and raw_value and prefix in self.evaluators:
                return self.evaluators[prefix](raw_value, parser_parameters)
            return default_evaluator(value, parser_parameters)

        return parse(query, parse_rule)

    parse_compound = parse

    def querify(self, obj, **parameters):
        parser_parameters = self.parameters.copy()
        if parameters:
            parser_parameters.update(parameters)
        def parenthize(objs):
            for obj in objs:
                if isinstance(obj, (rules.AnyRule, rules.AllRule)):
                    yield '({0})'.format(self.querify(obj))
                else:
                    yield self.querify(obj)

        if isinstance(obj, rules.NotRule):
            return 'not ' + ''.join(parenthize([obj.rule]))
        if isinstance(obj, rules.AnyRule):
            return ' or '.join(parenthize(obj.rules))
        if isinstance(obj, rules.AllRule):
            return ' and '.join(parenthize(obj.rules))
        if isinstance(obj, parser_parameters['default_rule']):
            return obj.expr
        for prefix, base in self.registry.items():
            if isinstance(obj, base):
                return prefix + '@' + obj.expr
        raise Exception('Not defined for {0}'.format(repr(obj.__class__.__name__)))


compound = Query()
compound.register(None, rules.GlobRule, 'glob')
compound.register('G', rules.GrainRule, 'grain')
compound.register('I', rules.PillarRule, 'pillar')
compound.register('E', rules.PCRERule, 'pcre')
compound.register('P', rules.GrainPCRERule, 'grain_pcre')
compound.register('S', rules.SubnetIPRule)
compound.register('X', rules.ExselRule, 'exsel')
compound.register('D', rules.LocalStoreRule)
compound.register('R', rules.YahooRangeRule)
compound.register('L', ListEvaluator, 'list')
compound.register('N', NodeGroupEvaluator)
