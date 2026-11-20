from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from paw.core.index import _init_db
from paw.web import api


class QueryPagination(unittest.IsolatedAsyncioTestCase):
    async def test_cursor_advances_over_unstable_cases(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            cases, jobs = root/'cases', root/'jobs'
            cases.mkdir()
            jobs.mkdir()
            with closing(sqlite3.connect(cases/'index.db')) as conn, conn:
                _init_db(conn)
                for name, status in (('a', 'running'), ('b', 'interrupted'), ('c', 'incomplete')):
                    directory = cases / ('case-' + name)
                    directory.mkdir()
                    (directory/'execution.json').write_text(json.dumps({'status':status}))
                    conn.execute('INSERT INTO cases(id) VALUES (?)', (name,))
                    conn.execute('INSERT INTO indicators VALUES (?,?,?)', (name,'domain','fixture.invalid'))
            with patch.multiple(api, CASES_DIR=cases, JOBS_DIR=jobs, DATA_DIR=root):
                query = api.CaseQuery(query_type='domain', value='fixture.invalid', limit=1)
                for expected, cursor in (([], 'a'), (['b'], 'b'), (['c'], None)):
                    result = await api.query_cases(query)
                    self.assertEqual([row['id'] for row in result['matches']], expected)
                    self.assertEqual(result['next_after'], cursor)
                    query.after = cursor
