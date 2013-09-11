'''

salt.targeting.parser
~~~~~~~~~~~~~~~~~~~~~


'''

from functools import wraps
import re

__all__ = [
    'to_python',
    'parse',
]

tokenize = re.compile(r'''
    (?P<and_stmt> \band(?=[\s$]) ) |
    (?P<or_stmt> \bor(?=[\s$]) ) |
    (?P<not_stmt> \bnot(?=[\s$]) ) |
    (?P<sub_query> \(.+\s.+\)(?!\S) ) |
    (?P<rule> \S+ )
''', flags=re.VERBOSE | re.MULTILINE | re.X).finditer


def parse(query, parse_rule):
    python_stmt = to_python(query)
    return eval(python_stmt, {'parse_rule': parse_rule})

def to_python(source):
    parser = QueryState()
    builder = []
    for each in tokenize(source):
        dispatch = getattr(parser, each.lastgroup)
        dispatch(each.group(), builder)
    return ' '.join(builder)


def transition(method):
    @wraps(method)
    def trans(state, *args, **kwargs):
        command = method(state, *args, **kwargs)
        state.__class__ = command(state)
    return trans


def unchanged(state):
    return state.__class__


def shifting(identity):
    def command(state):
        return identity
    return command


def pushing(identity, afterwards=None):
    def command(state):
        state._identities.append(afterwards or state.__class__)
        return identity
    return command


def popped(state):
    return state._identities.pop()


class State(object):
    def __new__(cls):
        state = object.__new__(cls)
        state._identities = []
        return state


class ParsingState(State):
    def __getattr__(self, name):
        def raiser(token, *args):
            raise ValueError(
                'parsing state %s does not understand token "%s" of type %s' %
                (self.__class__.__name__, token, name)
            )
        return raiser


class QueryState(ParsingState):
    @transition
    def sub_query(self, data, builder):
        builder.append('(' + to_python(data[1:-1]) + ')')
        return pushing(GroupState)

    @transition
    def rule(self, data, builder):
        builder.append('parse_rule(' + repr(data) + ')')
        return pushing(GroupState)

    @transition
    def not_stmt(self, data, builder):
        builder.append('-')
        return unchanged


class GroupState(ParsingState):
    @transition
    def and_stmt(self, data, builder):
        builder.append('&')
        return shifting(QueryState)

    @transition
    def or_stmt(self, data, builder):
        builder.append('|')
        return shifting(QueryState)

    def rule(self, data, builder):
        raise ValueError(
            'Statement is missing before {0} rule'.format(repr(data))
        )
