import asyncio
import time
import datetime
import re


_timedelta_regex = re.compile(r'((?P<weeks>\d+?)w)?((?P<days>\d+?)d)?((?P<hours>\d+?)h)?((?P<minutes>\d+?)m)?((?P<seconds>\d+?)s)?')


def parse_interval(interval):
    parts = _timedelta_regex.match(interval)
    if not parts:
        raise ValueError('%s is not a valid interval' % (interval, ))
    parts = parts.groupdict()
    time_params = {}
    for name, param in parts.items():
        if param:
            time_params[name] = int(param)
    return datetime.timedelta(**time_params).total_seconds()


class Timer:
    def __init__(self, interval, immediately=False, strict=False, limit_times=None):
        if isinstance(interval, str):
            interval = parse_interval(interval)
        self.interval = float(interval)
        self.immediately = immediately
        self.strict = strict
        self.limit_times = limit_times
        self.repeat_times = 0
        self.last_called = None

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.limit_times is not None and self.repeat_times > self.limit_times:
            raise StopAsyncIteration()
        delay = self.interval if not self.strict or self.last_called is None else \
            (delay + self.last_called - time.time())
        self.last_called = time.time()
        if self.repeat_times == 0 and self.immediately:
            return self.repeat_times
        self.repeat_times += 1
        await asyncio.sleep(delay)
        return self.repeat_times
