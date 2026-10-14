import json
import os
from pathlib import Path

import tmp.tmp as tmp

unresolved_http = []

traceability = dict()
traceability["nodes"] = dict()
traceability["edges"] = dict()


def merge_trace(record, location):
    locations = record.setdefault("locations", [])
    if location not in locations:
        locations.append(location)
    # Legacy readers still have a primary location; repeated traces retain sub_items.
    record.update(locations[0])


def add_trace(traceability_info: dict):
    """Retain every distinct location, including annotation subtraces."""
    item = traceability_info["item"]
    parent = traceability_info.get("parent_item")
    section = "edges" if "->" in (parent or item) else "nodes"
    records = traceability[section]
    if parent is not None:
        if parent not in records:
            return
        records = records[parent].setdefault("sub_items", {})
    record = records.setdefault(item, {})
    merge_trace(record, {"file": traceability_info["file"],
                         "line": traceability_info["line"],
                         "span": str(traceability_info["span"])})


def revert_flow(old_sender: str, old_receiver: str):
    """Reverse all witnesses without overwriting an existing reverse trace."""
    edges = traceability["edges"]
    old = old_sender + " -> " + old_receiver
    new = old_receiver + " -> " + old_sender
    if old == new or old not in edges:
        return
    incoming = edges.pop(old)
    target = edges.setdefault(new, {})
    for location in incoming["locations"]:
        merge_trace(target, location)
    for item, record in incoming.get("sub_items", {}).items():
        sub = target.setdefault("sub_items", {}).setdefault(item, {})
        for location in record["locations"]:
            merge_trace(sub, location)


def output_traceability():
    """Cleans the traceability dict and writes it to an output file.
    """

    quotate_ids()
    write_to_file()

    return traceability


def quotate_ids():
    """Puts double quotes around all ids from sub_items to make it readable.
    """

    global traceability

    new_traceability = dict()

    for trace in traceability:
        if "sub_items" in traceability[trace]:
            new_subs = dict()
            for sub_trace in traceability[trace]["sub_items"]:
                new_subs[str(sub_trace)] = traceability[trace]["sub_items"][sub_trace]
            traceability[trace]["sub_items"] = new_subs

        new_traceability[str(trace)] = traceability[trace]
    traceability = new_traceability


def write_to_file():
    """Writes tracebility info from dict to json file.
    """

    output_path = tmp.tmp_config["Analysis Settings"]["output_path"]
    parts = Path(output_path).parts
    filename = f"{parts[-2]}--{parts[-1]}_traceability.json"
    output_path = os.path.join(output_path, filename)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as architecture_file:
        json.dump(traceability, architecture_file, indent=4)
