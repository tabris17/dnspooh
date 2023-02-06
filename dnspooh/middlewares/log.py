import logging
import sqlite3
import time

import dnslib

from . import Middleware, Traceback


logger = logging.getLogger(__name__)


CREATE_DATABASE_SQL = \
'''CREATE TABLE IF NOT EXISTS "log" (
    "id"            INTEGER,
    "created_at"    TEXT,
    "elapsed_time"  REAL,
    "qname"         TEXT,
    "qtype"         TEXT,
    "success"       INTEGER,
    "request"       BLOB,
    "response"      BLOB,
    "traceback"     TEXT,
    "error"         TEXT,
    PRIMARY KEY("id" AUTOINCREMENT)
);
'''

INSERT_FAILURE_SQL = \
'''INSERT INTO "log" 
    (created_at, elapsed_time, qname, qtype, success, request, error, traceback) 
    VALUES 
    (:now, :elapsed_time, :qname, :qtype, :success, :request, :error, :traceback)
'''

INSERT_SUCCESS_SQL = \
'''INSERT INTO "log" 
    (created_at, elapsed_time, qname, qtype, success, request, response, traceback) 
    VALUES 
    (:now, :elapsed_time, :qname, :qtype, :success, :request, :response, :traceback)
'''


class LogMiddleware(Middleware):
    def __init__(self, path, trace, payload):
        self.path = path
        self.trace = trace
        self.payload = payload
        sqlite3.register_adapter(Traceback, self._adapt_traceback)
        with self._open_db() as db:
            db.execute(CREATE_DATABASE_SQL)

    def _adapt_traceback(self, traceback):
        return str(traceback)

    def _open_db(self):
        return sqlite3.connect(self.path)

    async def handle(self, request, **kwargs):
        if self.trace:
            kwargs['traceback'] = traceback = Traceback()
        else:
            traceback = None
        params = {
            'now': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
            'qname': str(request.q.qname),
            'qtype': dnslib.QTYPE[request.q.qtype],
            'request': request.pack() if self.payload else None,
            'traceback': traceback,
        }

        start_counter = time.perf_counter()
        try:
            response = await super().handle(request, **kwargs)
        except Exception as exc:
            params |= {'success': False, 'error': str(exc), 'elapsed_time': time.perf_counter() - start_counter}
            with self._open_db() as db: db.execute(INSERT_FAILURE_SQL, params)
            raise
        if response is None:
            params |= {'success': False, 'error': 'N/A', 'elapsed_time': time.perf_counter() - start_counter}
            with self._open_db() as db: db.execute(INSERT_FAILURE_SQL, params)
        else:
            params |= {
                'success': True, 
                'response': response.pack() if self.payload else None, 
                'elapsed_time': time.perf_counter() - start_counter
            }
            with self._open_db() as db: db.execute(INSERT_SUCCESS_SQL, params)
        return response
