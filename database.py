#!/usr/bin/python
# pip install mysql-connector-python-rf
# pip install GitPython
import socket
import time
import git
import mysql.connector

class Database:
    fields = [
        ["test_name", "varchar(64)"],
        ["build_type", "varchar(16)"],
        ["git_sha", "varchar(40)"],
        ["test_datetime", "DATETIME"],
    ]

    def __init__(self):
        self.sql_conn = None
        self.sql_cursor = None

        repo = git.Repo(search_parent_directories=True)
        self.git_sha = repo.head.commit.hexsha
        changed = [item.a_path for item in repo.index.diff(None)]
        self.git_changed = len(changed) > 0

    def __del__(self):
        if self.sql_conn:
            self.sql_conn.close()
            self.sql_conn = None

    def create_table(self):
        columns = unique = ""		 

        for field in self.fields:
            if columns:
                columns += ", "
                unique += ", "
            columns += field[0] + " " + field[1]
            unique += field[0]

        self.execute("create table if not exists test ("
            "id int auto_increment,"
            "%s,"
            "primary key(id),"
            "unique key(%s)"
        ")" % (columns, unique))

    def execute(self, cmd, *args):
        if self.sql_conn == None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            rc = sock.connect_ex(('127.0.0.1', 3306))
            sock.close()
            if rc != 0:
                return
            self.sql_conn = mysql.connector.connect(user='root')
            self.execute("create database if not exists gbtcp")
            self.sql_conn.close()
            self.sql_conn = mysql.connector.connect(user='root', database='gbtcp')
            self.create_table()

        try:
            self.sql_cursor = self.sql_conn.cursor(buffered = True)
            self.sql_cursor.execute(cmd, *args);
        except mysql.connector.errors.ProgrammingError as exc:
            raise RuntimeError("mysql query '%s' failed" % cmd) from exc

    def get_columns(self, table):
        cmd = "show columns from %s" % table

        columns = []
        self.execute(cmd)
        if self.sql_cursor == None:
            return []
        while True:
            rows = self.sql_cursor.fetchone()
            if rows == None:
                break
            columns.append(rows[0])
        self.sql_cursor.close()
        return columns

    def alter_add_columns(self, table, columns):
        if not columns:
            return
        cmd = "alter table %s" % table
        for i, column in enumerate(columns):
            if i:
                cmd += ", "
            else:
                cmd += " "
            cmd += "add column %s bigint" % column
        self.execute(cmd)
        self.commit()

    def commit(self):
        if self.sql_conn != None:
            self.sql_cursor.close()
            self.sql_cursor = None
            self.sql_conn.commit()
#            self.sql_conn.close()
#            self.sql_conn = None

    def insert(self, test_name, build_type, output):
        new_columns = []
        columns = self.get_columns("test")
        for key in output.keys():
            if key not in columns:
                new_columns.append(key)

        self.alter_add_columns("test", new_columns)

        fields = {}
        fields['test_name'] = test_name
        fields['build_type'] = build_type
        fields['git_sha'] = self.git_sha
        if self.git_changed:
            t = time.localtime()
            fields['test_datetime'] = time.strftime("%Y-%m-%d %H:%M:%S", t)

        where = keys = values = ""

        fields_output = dict(fields)
        fields_output.update(output)

        for key, value in fields_output.items():
            if type(value) == int:
                s = str(value)
            else:
                s = '"' + value + '"'

            if key in fields:
                if where:
                    where += " and "
                where += key + "=" + s

            if keys:
                keys += ", "
            keys += key
            if values:
                values += ", "
            values += s

        cmd = ("insert into test (%s) select %s where not exists (select 1 from test where %s)"
            % (keys, values, where))
        self.execute(cmd)
        self.commit()
