"""Local snapshot adapter for Code2DFD: no Git operations, servers or rendering.

The legacy DFD extraction/classification pipeline remains the analysis engine.
Only structural/security labels and locations are exported; URLs, credentials,
properties and tagged-value contents are deliberately omitted.
"""

import argparse
import contextlib
import io
import json
from pathlib import Path

import tmp.tmp as tmp
from core.dfd_extraction import DFD_extraction
from output_generators import traceability
from technology_specific_extractors.quarkus.qrs_entry import extract as extract_quarkus

COMMUNICATIONS = [('RabbitMQ', 'rmq'), ('Kafka', 'kfk'), ('RestTemplate', 'rst'),
                  ('FeignClient', 'fgn'), ('Implicit Connections', 'imp'),
                  ('Database Connections', 'dbc'), ('HTML', 'html'), ('Docker-Compose', 'dcm')]


def location(trace, root):
    if not trace or not isinstance(trace.get('file'), str):
        return None, None
    path = Path(trace['file'])
    if path.is_absolute():
        try:
            path = path.relative_to(root)
        except ValueError:
            return None, None
    if '..' in path.parts or not (root / path).is_file():
        return None, None
    value = trace.get('line')
    # Legacy grep evidence is a one-based string; parser indices are zero-based ints.
    if isinstance(value, str) and value.isdecimal():
        line = int(value)
    elif type(value) is int and value >= 0:
        line = value + 1
    else:
        return None, None
    return path.as_posix(), line


def analyze(root):
    tmp.tmp_config.clear()
    traceability.traceability = {'nodes': {}, 'edges': {}}
    for section in ('Repository', 'Technology Profiles', 'Analysis Settings', 'DFD'):
        tmp.tmp_config.add_section(section)
    tmp.tmp_config.set('Repository', 'local_path', str(root))
    tmp.tmp_config.set('Analysis Settings', 'headless', 'True')
    tmp.tmp_config.set('Technology Profiles', 'communication_techs_list', str(COMMUNICATIONS))
    with contextlib.redirect_stdout(io.StringIO()):
        services, flows, external = DFD_extraction(write_outputs=False)
    nodes = []
    for raw in (*(services or {}).values(), *(external or {}).values()):
        name = raw['name']
        marker = raw.get('pom_path') or raw.get('gradle_path')
        trace = traceability.traceability['nodes'].get(name)
        if trace is None:
            trace = traceability.traceability['nodes'].get(name.removeprefix('pom_'))
        file, line = location(trace, root)
        nodes.append({'name': name, 'root': str(Path(marker).parent) if marker else None,
                      'stereotypes': sorted(set(raw.get('stereotype_instances', ()))),
                      'file': file, 'line': line})
    result_flows = []
    for raw in (flows or {}).values():
        sender, receiver = raw['sender'], raw['receiver']
        trace = traceability.traceability['edges'].get(f'{sender} -> {receiver}')
        file, line = location(trace, root)
        result_flows.append({'sender': sender, 'receiver': receiver,
                             'stereotypes': sorted(set(raw.get('stereotype_instances', ()))),
                             'file': file, 'line': line})
    quarkus_flows, coverage = extract_quarkus(root, nodes)
    result_flows.extend(quarkus_flows)
    coverage.insert(0, {'file': '.', 'line': 0,
                       'detail': 'Code2DFD uses bounded heuristic extraction. '
                                 'Reachability, profiles, serializers and complete framework '
                                 'coverage are not established; Quarkus clients require '
                                 'literal annotations and application.properties bindings.'})
    return {'schema_version': 1, 'engine': 'code2dfd', 'nodes': nodes,
            'flows': result_flows, 'coverage': coverage}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(analyze(args.target.resolve()), sort_keys=True))


if __name__ == '__main__':
    main()
