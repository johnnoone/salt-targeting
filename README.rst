Salt Targeting
==============

This repository is a work in progress in order to refactor targeting into `Salt Stack`_.

The primary goals are :

  - debug compound query parsing
  - make PCRE matching absolute
  - fix foo:bar expressions (aka digging)
  - debug current targeting (make PCRE matching absolute, fix parsing)
  - make the compound matching the default
  - unify all targetings (CLI, top.sls, mine, peering...)

The secondary goals are :

  - simplify API to create new query parsers and extends with new rules
  - allow digging in module config.option
  - etc.


Composing a query
-----------------

High level: express a query
~~~~~~~~~~~~~~~~~~~~~~~~~~~

ABNF:

.. code:: abnf

    expr = 1*CHAR
    prefix = 1ALPHA
    rule = [prefix "@"] expr
    query = rule / "(" query ")" / "not " query / query " and " query / query " or " query

Query examples:

.. code:: text

    *.example.com
    not example.com
    *.example.com and not (I@"fullname:John Doe" or D@role:web)

Query expressions implements **or**, **and**, **not** and **tuple display** operators, and they have the same precedences than Python. Other characters are evaluated as rule expression.


Middle level: parsing query
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

    parse('*.example.com')
    parse('not example.com')
    parse('*.example.com and not (I@fullname:John Doe or D@role:web)')

Normalization

`EXPR` can contains parenthizes and inner spaces. Any redondant spaces will be normalize to a single one.

.. code:: python

    assert normalize('G@foo:   bar baz)  ') == 'G@foo: bar baz)'

Precedence

or	Boolean OR
and	Boolean AND
not x
(expressions...) Binding or tuple display

In case of mixin operators, these queries are equivalents:

.. code:: python

    assert parse('foo or bar and baz or qux') == parse('qux or foo or (baz and bar)')
    assert parse('foo and bar or baz and qux') == parse('(qux and baz) or (foo and bar)')

Fallback

try to assign to prefixed rule. fallback to GlobRule if none match.

Low level: building query
~~~~~~~~~~~~~~~~~~~~~~~~~

pur python composing:

.. code:: python

    GlobRule('*.example.com')
    NotRule(GlobRule('example.com'))
    AllRule(GlobRule('*.example.com'), NotRule(AnyRule(PillarRule('fullname:John Doe'), DataRule('role:web'))))

operator composing:

.. code:: python

    GlobRule('*.example.com')
    - GlobRule('example.com')
    GlobRule('*.example.com') & - (PillarRule('fullname:John Doe') or DataRule('role:web'))


Machinery
---------

:subjects:

  A subject is an adapter that represent a single minion. Implements id,
  grains, pillar... any attribute used by rules.

:rules:

  A rule is the lower component for matching or filtering based on subject's
  attributes. They implements match (for exact matching) and check (for a bref
  check over a list of minion).

  - GlobRule: performs a glob search based on the minion id
  - PCRERule (E@): performs a pcre search on minion id
  - GrainRule (G@): performs a glob search on grains
  - GrainPCRERule (P@): performs a pcre search on grains
  - PillarRule (I@): performs a glob search on pillar
  - SubnetIPRule (S@): performs a search on minion ip/interface
  - ExselRule (X@): execute a minion.function that should return true or false
  - LocalStoreRule (D@): performs a pcre search on minion local data
  - YahooRangeRule (R@): performs a yahoo range matching

:operators:

  - NotRule (not): negates inner Rule
  - AllRule (and): all inner rules must match
  - AnyRule (or): at least one inner rule must match

:virtual rules:

  Virtual rules are syntaxique sugar in order to symplify query expressions.
  They must decompose given expr and returns the good query based on rules and
  keywords.

  - ListEvaluator (L@): shortcut for AnyRule(*default_rules)
  - NodeGroupEvaluator (N@) : shortcut allowed in the master side.

Examples:

.. code:: python

  rule = GlobRule('*example.com')
  rule.match(minion)
  rule.check(minions)

  query1 = parse('foo or bar')
  query2 = parse('L@foo,bar')
  query3 = AnyRule(GlobRule('foo'), GlobRule('bar'))
  query4 = GlobRule('foo') | GlobRule('bar')
  assert query1 == query2 == query3 == query4

.. _`Salt Stack`: http://docs.saltstack.com/
