import json
import os
from datetime import datetime

PATH_PREFIX = "/tmp/ospf_archive/"


def archive_event_message(event: dict):
    event_time = datetime.fromtimestamp(event["timestamp"] / 1000)
    file_path = os.path.join(PATH_PREFIX, event_time.strftime("%Y/%m/%d/%H") + ".jsonl")
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "a") as f:
        f.write(json.dumps(event) + "\n")


def archive_db_snapshot(api_payload: dict):
    api_snapshot_time = datetime.fromtimestamp(api_payload["updated"] / 1000)
    file_path = os.path.join(
        PATH_PREFIX,
        "snapshots",
        api_snapshot_time.strftime("%Y/%m/%d/%H/%M") + ".json",
    )
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w") as f:
        f.write(json.dumps(api_payload))
