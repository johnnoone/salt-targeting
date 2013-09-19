'''

salt.targeting
~~~~~~~~~~~~~~


'''

import logging
log = logging.getLogger(__name__)

from .parser import *
from .query import *
from .rules import *
from .subjects import *

#: defines minion targeting
minion_targeting = Query(default_rule=GlobRule)
minion_targeting.register(GlobRule, None, 'glob')
minion_targeting.register(GrainRule, 'G', 'grain')
minion_targeting.register(PillarRule, 'I', 'pillar')
minion_targeting.register(PCRERule, 'E', 'pcre')
minion_targeting.register(GrainPCRERule, 'P', 'grain_pcre')
minion_targeting.register(SubnetIPRule, 'S')
minion_targeting.register(ExselRule, 'X', 'exsel')
minion_targeting.register(LocalStoreRule, 'D')
minion_targeting.register(YahooRangeRule, 'R')
minion_targeting.register(ListEvaluator, 'L', 'list')
minion_targeting.register(NodeGroupEvaluator, 'N')

