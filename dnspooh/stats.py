import asyncio
import enum
import time

from collections import deque

from .exceptions import EmptyValueError, UnexpectedValueError


class Stats:
    class Record:
        class Result(enum.Enum):
            SUCCESS = enum.auto()
            TIMEOUT = enum.auto()
            ERROR = enum.auto()
            EMPTY = enum.auto()
            INVALID = enum.auto()

            def __repr__(self):
                return self.name

        def __init__(self, stats, upstream):
            self.stats = stats
            self.upstream = upstream

        def __enter__(self):
            self.start_time = time.perf_counter()
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            self.upstream.usage += 1
            if exc_type is None:
                self.upstream.success += 1
                self.result = self.Result.SUCCESS
            else:
                if isinstance(exc_type, (TimeoutError, asyncio.exceptions.TimeoutError)):
                    self.result = self.Result.TIMEOUT
                elif isinstance(exc_type, EmptyValueError):
                    self.result = self.Result.EMPTY
                elif isinstance(exc_type, UnexpectedValueError):
                    self.result = self.Result.INVALID
                else:
                    self.result = self.Result.ERROR

            self.elapsed_time_sec = time.perf_counter() - self.start_time
            self.stats.records.append(self)
            del self.stats

        def __repr__(self):
            return str(vars(self))

        def as_dict(self):
            return {
                'upstream': self.upstream.name,
                'start_time': self.start_time,
                'elapsed_time': self.elapsed_time_sec,
            }

    def __init__(self, maxlen):
        self.records = deque(maxlen=maxlen)

    def record(self, upstream):
        return self.Record(self, upstream)

    def __repr__(self):
        return str(vars(self))
