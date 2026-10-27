import glob
import sqlite3
import os

db_files = sorted(glob.glob('dataset/evidence/databases/*.sql'))

for db_path in db_files:
    fname = os.path.basename(db_path)
    con = sqlite3.connect(':memory:')
    with open(db_path, 'r', encoding='utf-8') as f:
        con.executescript(f.read())
    c = con.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [r[0] for r in c.fetchall()]
    all_cols = {}
    for t in tables:
        c.execute(f'PRAGMA table_info("{t}");')
        cols = [r[1] for r in c.fetchall()]
        all_cols[t] = cols
    print(f"{fname}: {all_cols}")
    con.close()
