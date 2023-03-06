import datetime
import re
import sqlite3

import leaktopus.common.contributors as contributors
import leaktopus.common.db_updates as db_updates
import leaktopus.common.scans as scans
import leaktopus.common.sensitive_keywords as sensitive_keywords
import leaktopus.common.updates as updates
from flask import Flask, g, abort, current_app
from leaktopus.utils.common_imports import logger

app = Flask(__name__)


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def regexp(expr, item):
    return re.search(rf"{expr}", item) is not None


def init_config_github_ignore(db):
    cursor = db.cursor()
    # Install the default ignore list.
    cursor.execute(
        """INSERT OR IGNORE INTO config_github_ignore(pattern) VALUES
             ("^https://github.com/citp/privacy-policy-historical"),
             ("^https://github.com/haonanc/GDPR-data-collection"),
             ("^https://github.com/[\w\-]+/dmca")
             """
    )
    db.commit()


def db_install(db):
    """
    First time DB initialization.
    :param db:
    :return:
    """

    cursor = db.cursor()
    cursor.execute(
        """
            CREATE TABLE if not exists leak(
                pid INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                search_query TEXT,
                leak_type TEXT,
                context TEXT,
                leaks TEXT,
                acknowledged TINYINT,
                last_modified INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )"""
    )

    cursor.execute(
        """
            CREATE TABLE if not exists secret(
                pid INTEGER PRIMARY KEY AUTOINCREMENT,
                leak_id INTEGER,
                url TEXT,
                signature_name TEXT,
                match_string TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )"""
    )

    cursor.execute(
        """
            CREATE TABLE if not exists domain(
                pid INTEGER PRIMARY KEY AUTOINCREMENT,
                leak_id INTEGER,
                url TEXT,
                domain TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )"""
    )

    cursor.execute(
        """
            CREATE TABLE if not exists config_github_ignore(pid INTEGER PRIMARY KEY AUTOINCREMENT, pattern TEXT UNIQUE)
            """
    )

    cursor.execute(
        """
                CREATE TABLE if not exists alert(
                    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sent_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    leak_id INTEGER,
                    type TEXT
                )"""
    )
    cursor.execute(
        """
            CREATE TABLE IF NOT exists scan_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                page_number INTEGER,
                status TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
        """
    )

    cursor.execute(
        """
            CREATE TABLE IF NOT exists enhancement_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                leak_url TEXT,
                search_query TEXT,
                module_key TEXT,
                last_modified TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
        """
    )
    db.commit()

    # Make some further installation steps.
    init_config_github_ignore(db)
    updates.db_install_updates(db)
    scans.db_install_scans(db)
    contributors.db_install_contributors(db)
    sensitive_keywords.db_install_sensitive_keywords(db)

    # Update the DB with the latest updates version.
    db_updates.apply_db_updates(True)


class Metrics:
    def __init__(self):
        self.collected = {}

    def started(self, name):
        self.start_time = datetime.datetime.now()
        self.collected[name] = self.start_time

    def get_time_diff(self, name):
        diff = datetime.datetime.now() - self.collected[name]
        logger.debug("%s: Time diff: %s seconds", name, diff.total_seconds())
        return diff.total_seconds()


def get_leak(**kwargs):
    m = Metrics()
    m.started("get_leak")
    try:
        sql_cond = []
        sql_vars = ()
        for col in kwargs.keys():
            sql_vars = (*sql_vars, kwargs[col])
            sql_cond.append(col)

        cur = get_db().cursor()
        if sql_vars:
            where_str = ("=? AND ").join(sql_cond) + "=?"
            # @todo Replace this dirty workaround in a way that supports operators.
            where_str = where_str.replace("created_at=?", "created_at>?")
            m.started("sql_vars")
            stmt = "SELECT * FROM leak WHERE " + where_str + " ORDER BY created_at DESC"
            res = cur.execute(
                stmt,
                sql_vars,
            )
            m.get_time_diff("sql_vars")
            logger.debug("sql_vars stmt: %s\n%s", stmt, sql_vars)
        else:
            m.started("no_sql_vars")
            stmt = "SELECT * FROM leak ORDER BY created_at DESC"
            res = cur.execute(stmt)
            m.get_time_diff("no_sql_vars")
            logger.debug("no_sql_vars stmt: %s", stmt)

        m.started("fetchall leaks")
        leaks_res = res.fetchall()
        m.get_time_diff("fetchall leaks")
        # @todo Replace the secrets fetching with one query with join and grouping.
        for i in range(len(leaks_res)):
            stmt = "SELECT * FROM secret WHERE leak_id=? ORDER BY created_at DESC"
            m.started("secrets_res")
            secrets_res = cur.execute(
                stmt,
                (leaks_res[i]["pid"],),
            )
            leaks_res[i]["secrets"] = secrets_res.fetchall()
            m.get_time_diff("secrets_res")
            logger.debug("secrets_res stmt: %s\n%s", stmt, (leaks_res[i]["pid"],))

            stmt = "SELECT * FROM domain WHERE leak_id=? ORDER BY created_at DESC"
            m.started("domains_res")
            domains_res = cur.execute(
                stmt,
                (leaks_res[i]["pid"],),
            )
            leaks_res[i]["domains"] = domains_res.fetchall()
            m.get_time_diff("domains_res")
            logger.debug("domains_res stmt: %s\n%s", stmt, (leaks_res[i]["pid"],))

            m.started("get_contributors")
            stmt = "SELECT id, name, author_email, committer_email, is_organization_domain FROM contributors WHERE leak_id=? ORDER BY created_at DESC"
            domains_res = cur.execute(
                stmt,
                (leaks_res[i]["pid"],),
            )
            leaks_res[i]["contributors"] = domains_res.fetchall()
            m.get_time_diff("get_contributors")
            logger.debug("get_contributors stmt: %s\n%s", stmt, (leaks_res[i]["pid"],))

            m.started("get_sensitive_keywords")
            stmt = "SELECT id, keyword, url FROM sensitive_keywords WHERE leak_id=? ORDER BY created_at DESC"
            domains_res = cur.execute(
                stmt,
                (leaks_res[i]["pid"],),
            )
            leaks_res[i]["sensitive_keywords"] = domains_res.fetchall()
            m.get_time_diff("get_sensitive_keywords")

        m.get_time_diff("get_leak")
        return leaks_res

    except Exception as e:
        logger.error("Error while getting leak data from DB - {}", e)
        abort(500)


def get_secret(**kwargs):
    try:
        sql_cond = []
        sql_vars = ()
        for col in kwargs.keys():
            sql_vars = (*sql_vars, kwargs[col])
            sql_cond.append(col)

        cur = get_db().cursor()
        if sql_vars:
            where_str = ("=? AND ").join(sql_cond) + "=?"
            res = cur.execute(
                "SELECT * FROM secret WHERE " + where_str + " ORDER BY created_at DESC",
                sql_vars,
            )
        else:
            res = cur.execute("""SELECT * FROM secret ORDER BY created_at DESC""")
        return res.fetchall()

    except Exception as e:
        abort(500)


def add_secret(leak_id, url, signature_name, match_string):
    try:
        # Insert or ignore if already exists
        db = get_db()

        cursor = db.cursor()
        cursor.execute(
            """
                INSERT OR IGNORE INTO secret(leak_id, url, signature_name, match_string)
                    VALUES(?,?,?,?)
                """,
            (
                leak_id,
                url,
                signature_name,
                match_string,
            ),
        )
        db.commit()
        return cursor.lastrowid

    except Exception as e:
        abort(500)


def get_domain(**kwargs):
    sql_cond = []
    sql_vars = ()
    for col in kwargs.keys():
        sql_vars = (*sql_vars, kwargs[col])
        sql_cond.append(col)

    cur = get_db().cursor()
    if sql_vars:
        where_str = ("=? AND ").join(sql_cond) + "=?"
        res = cur.execute(
            "SELECT * FROM domain WHERE " + where_str + " ORDER BY created_at DESC",
            sql_vars,
        )
    else:
        res = cur.execute("""SELECT * FROM domain ORDER BY created_at DESC""")
    return res.fetchall()


def add_domain(leak_id, url, domain):
    # Insert or ignore if already exists
    db = get_db()

    cursor = db.cursor()
    cursor.execute(
        """
            INSERT OR IGNORE INTO domain(leak_id, url, domain)
                VALUES(?,?,?)
            """,
        (
            leak_id,
            url,
            domain,
        ),
    )
    db.commit()
    return cursor.lastrowid


# @todo Consider to use **kwargs instead.
def add_leak(url, search_query, leak_type, context, leaks, acknowledged, last_modified):
    try:
        # Insert or ignore if already exists
        db = get_db()

        cursor = db.cursor()
        cursor.execute(
            """
            INSERT OR IGNORE INTO leak(url, search_query, leak_type, context, leaks, acknowledged, last_modified)
                VALUES(?,?,?,?,?,?,?)
            """,
            (
                url,
                search_query,
                leak_type,
                context,
                leaks,
                acknowledged,
                last_modified,
            ),
        )
        db.commit()
        return cursor.lastrowid

    except Exception as e:
        abort(500)


def update_leak(leak_id, **kwargs):
    # Insert or ignore if already exists
    db = get_db()

    # @todo Find a prettier way to do the dynamic update.
    for col in kwargs.keys():
        col_sql = col + "=?"
        db.cursor().execute(
            "UPDATE leak SET " + col_sql + " WHERE pid=?",
            (
                kwargs[col],
                leak_id,
            ),
        )
    db.commit()


def delete_leak_by_url(url):
    db = get_db()
    cur = db.cursor()

    cur.execute("""DELETE FROM leak WHERE url REGEXP ?""", (url,))
    # @todo Get the leak id and delete by it.
    cur.execute("""DELETE FROM secret WHERE url REGEXP ?""", (url,))
    cur.execute("""DELETE FROM domain WHERE url REGEXP ?""", (url,))
    # cur.execute('''DELETE FROM contributors WHERE url REGEXP ?''', (url,))
    # cur.execute('''DELETE FROM sensitive_keywords WHERE url REGEXP ?''', (url,))

    db.commit()


def get_config_github_ignored():
    cur = get_db().cursor()
    res = cur.execute("""SELECT pid as id, pattern FROM config_github_ignore""")
    return res.fetchall()


def add_config_github_ignored(pattern):
    try:
        # Insert or ignore if already exists
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            """INSERT OR IGNORE INTO config_github_ignore(pattern) VALUES(?)""",
            (pattern,),
        )
        db.commit()
        return cursor.lastrowid
    except Exception as e:
        abort(500)


def delete_config_github_ignored(pid):
    try:
        # Insert or ignore if already exists
        db = get_db()
        db.cursor().execute("""DELETE FROM config_github_ignore WHERE pid=?""", (pid,))
        db.commit()
    except Exception as e:
        abort(500)


def get_db(force_install=False):
    db = getattr(g, "_database", None)
    if db is None:
        g._database = db = get_db_connection(current_app.config["DATABASE_PATH"])

        # @todo Refactor and use a migration solution.
        db_install(db)

    return db


def get_db_connection(database_file_path):
    db = sqlite3.connect(database_file_path, timeout=20)
    db.create_function("REGEXP", 2, regexp)
    db.row_factory = dict_factory
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()
