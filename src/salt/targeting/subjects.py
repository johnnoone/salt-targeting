'''

salt.targeting.subjects
~~~~~~~~~~~~~~~~~~~~~~~


'''

from salt.utils import lazy_property
import logging
log = logging.getLogger(__name__)

__all__ = [
    'Subject',
    'CheckableMinion',
    'MatchableMinion',
]

class Subject(object):
    def __getattr__(self, attr):
        if attr in ('id', 'fqdn', 'ipv4', 'grains', 'pillar', 'data', 'functions'):
            return None
        raise AttributeError(attr)


class CheckableMinion(Subject):
    def __init__(self, id):
        self.id = id
        self.opts = opts

    @lazy_property
    def fqdn(self):
        try:
            self.cache['grains']['fqdn']
        except KeyError:
            return None

    @lazy_property
    def ipv4(self):
        try:
            self.cache['grains']['ipv4']
        except KeyError:
            return None

    @lazy_property
    def grains(self):
        try:
            self.cache['grains']
        except KeyError:
            return None

    @lazy_property
    def pillar(self):
        try:
            self.cache['pillar']
        except KeyError:
            return None

    @lazy_property
    def cache(self):
        if self.opts.get('minion_data_cache', False):
            try:
                serial = salt.payload.Serial(self.opts)
                return serial.load(
                    salt.utils.fopen(
                        os.path.join(
                            self.opts['cachedir'],
                            'minions', self.id, 'data.p'
                        )
                    )
                )
            except Exception as e:
                log.exception(e)
        return None


class MatchableMinion(Subject):
    def __init__(self, opts, funcs):
        self.opts = opts
        self.functions = funcs

    @property
    def id(self):
        self.opts['grains']['id']

    @property
    def fqdn(self):
        self.opts['grains']['fqdn']

    @property
    def ipv4(self):
        self.opts['grains']['ipv4']

    @property
    def grains(self):
        self.opts['grains']

    @property
    def pillar(self):
        self.opts['pillar']

    @lazy_property
    def data(self):
        self.funcs['data.load']()
