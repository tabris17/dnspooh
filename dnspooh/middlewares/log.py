import logging
import sqlite3
import time
import json

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

SELECT_DATASET_SQL = \
'''SELECT id, created_at, elapsed_time, qname, qtype, success, traceback, error 
    FROM "log" ORDER BY id DESC LIMIT :offset, :page_size
'''

QUERY_PAGE_SIZE = 50


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

    def query_dataset(self, page, page_size=QUERY_PAGE_SIZE):
        offset = (page - 1) * page_size
        with self._open_db() as db:
            result = db.execute(SELECT_DATASET_SQL, {
                'offset': offset,
                'page_size': page_size
            })
            field_names = [column[0] for column in result.description]
            def format_row(row):
                record = dict(zip(field_names, row))
                traceback = record['traceback']
                if traceback:
                    try:
                        record['traceback'] = json.loads(traceback)
                    except json.JSONDecodeError:
                        record['traceback'] = None
                return record
            return list(map(format_row, result))
            return [dict(zip(field_names, row)) for row in result]

    def query_total(self):
        with self._open_db() as db:
            result = db.execute('SELECT COUNT(*) FROM "log"')
            total, = result.fetchone()
            return total

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
