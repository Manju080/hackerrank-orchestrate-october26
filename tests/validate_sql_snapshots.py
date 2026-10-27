import glob
import sqlite3
import os

db_files = sorted(glob.glob('dataset/evidence/databases/*.sql'))
print(f"Total SQL files found: {len(db_files)}")

results = []
for db_path in db_files:
    fname = os.path.basename(db_path)
    con = sqlite3.connect(':memory:')
    try:
        with open(db_path, 'r', encoding='utf-8') as f:
            sql_content = f.read()
        con.executescript(sql_content)
        cursor = con.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [r[0] for r in cursor.fetchall()]
        table_counts = {}
        for t in tables:
            cursor.execute(f'SELECT COUNT(*) FROM "{t}";')
            table_counts[t] = cursor.fetchone()[0]
        results.append((fname, 'OK', len(tables), table_counts))
    except Exception as e:
        results.append((fname, f'FAIL: {e}', 0, {}))
    finally:
        con.close()

for r in results:
    print(f"{r[0]}: status={r[1]}, table_count={r[2]}, tables={r[3]}")
