import enum
import time

from collections import deque

from .exceptions import EmptyValueError, UnexpectedValueError


class Stats:
    class Record:
        class Result(enum.Enum):
            success = enum.auto()
            timeout = enum.auto()
            error = enum.auto()
            empty = enum.auto()
            invalid = enum.auto()

            def __repr__(self):
                return self.name

        def __init__(self, stats, upstream):
            self.stats = stats
            self.upstream = upstream

        def __enter__(self):
            self.start_time = time.time()
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            self.upstream.usage += 1
            if exc_type is None:
                self.upstream.success += 1
                self.result = self.Result.success
            else:
                if isinstance(exc_type, TimeoutError):
                    self.result = self.Result.timeout
                elif isinstance(exc_type, EmptyValueError):
                    self.result = self.Result.empty
                elif isinstance(exc_type, UnexpectedValueError):
                    self.result = self.Result.invalid
                else:
                    self.result = self.Result.error

            self.cost_time = time.time() - self.start_time
            self.stats.records.append(self)
            del self.stats

        def __repr__(self):
            return str(vars(self))

        def as_dict(self):
            return {
                'upstream': self.upstream.name,
                'start_time': self.start_time,
                'cost_time': self.cost_time,
            }

    def __init__(self, maxlen):
        self.records = deque(maxlen=maxlen)

    def record(self, upstream):
        return self.Record(self, upstream)

    def __repr__(self):
        return str(vars(self))