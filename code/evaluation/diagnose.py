import sys
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pandas as pd
from code.config import SAMPLE_OUTPUT_PATH, SAMPLE_DELETION_REQUESTS_PATH
from code.audit.identity import IdentityResolver

id_res = IdentityResolver()
df_req = pd.read_csv(SAMPLE_DELETION_REQUESTS_PATH).set_index("case_id")
df_gold = pd.read_csv(SAMPLE_OUTPUT_PATH).set_index("case_id")

all_match = True
for cid, row in df_gold.iterrows():
    req = df_req.loc[cid]
    user = id_res.resolve_by_email(req["email"], as_of_time=req["requested_at"])
    if not user:
        user = id_res.resolve_by_email(req["email"])
    uid = user.user_id if user else None
    if uid:
        acc_id = "account_" + uid.split("_")[1]
        steps = row["steps_json"]
        in_steps = acc_id in steps
        if not in_steps:
            print(f"NOT in steps: {cid} uid={uid} acc_id={acc_id}")
            all_match = False
        else:
            print(f"MATCH: {cid} -> {acc_id}")

print(f"All 32 cases match primary account pattern: {all_match}")

