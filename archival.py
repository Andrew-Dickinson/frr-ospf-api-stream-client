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
