'''

salt.targeting.parser
~~~~~~~~~~~~~~~~~~~~~


'''

from functools import wraps
import re
import logging
log = logging.getLogger(__name__)

__all__ = [
    'to_python',
    'parse',
    'tokenize',
]

tokenize = re.compile(r'''
    (?P<and_stmt> \band(?=[\s$]) ) |
    (?P<or_stmt> \bor(?=[\s$]) ) |
    (?P<not_stmt> \bnot(?=[\s$]) ) |
    (?P<sub_query> \(.+\s.+\)(?!\S) ) |
    (?P<expr> \S+ )

''', flags=re.VERBOSE | re.MULTILINE | re.X).finditer

def parse(query, parse_rule):
    python_stmt = to_python(query)
    try:
        return eval(python_stmt, {'parse_rule': parse_rule})
    except SyntaxError as e:
        log.exception(e)
        log.error('Query {0} has been parsed has {1}'.format(repr(query), repr(python_stmt)))
        raise SyntaxError('Unexpected error while parsing {0}'.format(repr(query)))

def to_python(source):
    parser = QueryState()
    builder = []
    for each in tokenize(source):
        dispatch = getattr(parser, each.lastgroup)
        dispatch(each.group(), builder)
    if builder and builder[-1] in ('-', '|', '&'):
        log.error('SyntaxError: {0} -> {1}'.format(repr(source), repr(builder)))
        raise SyntaxError('Unexpected operator at the end of {0}'.format(repr(source)))
    return ' '.join(builder)

def normalize(value):
    return ' '.join(value.strip().split())

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
    def expr(self, data, builder):
        builder.append('parse_rule(' + repr(data) + ')')
        return pushing(ExprState)

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

    def expr(self, data, builder):
        raise ValueError(
            'Statement is missing before {0} expr'.format(repr(data))
        )


class ExprState(GroupState):
    def expr(self, data, builder):
        # normalize space between 2 expr
        last = builder.pop()
        if last.startswith('parse_rule(') and last.endswith(')'):
            log.warning('Merging 2 following tokens')
            builder.append(last[:-1] + repr(' ') + repr(data) + last[-1])
            return unchanged
        return GroupState.expr(self, data, builder)
