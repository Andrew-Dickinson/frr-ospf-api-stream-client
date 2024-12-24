import json
import os
from datetime import datetime


def archive_event_message(event: dict, path_prefix: str):
    event_time = datetime.fromtimestamp(event["timestamp"] / 1000)
    file_path = os.path.join(path_prefix, event_time.strftime("%Y/%m/%d/%H") + ".jsonl")
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "a") as f:
        f.write(json.dumps(event) + "\n")


def archive_db_snapshot(api_payload: dict, path_prefix: str):
    api_snapshot_time = datetime.fromtimestamp(api_payload["updated"] / 1000)
    archival_file_path = os.path.join(
        path_prefix,
        api_snapshot_time.strftime("%Y/%m/%d/%H/%M") + ".json",
    )
    os.makedirs(os.path.dirname(archival_file_path), exist_ok=True)
    with open(archival_file_path, "w") as f:
        f.write(json.dumps(api_payload))

    current_file_path = os.path.join(
        path_prefix,
        "../../mesh_ospf_data.json",
    )
    with open(current_file_path, "w") as f:
        f.write(json.dumps(api_payload))
