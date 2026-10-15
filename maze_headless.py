"""Local snapshot adapter for Code2DFD: no Git operations, servers or rendering.

The legacy DFD extraction/classification pipeline remains the analysis engine.
Only structural/security labels and locations are exported; URLs, credentials,
properties and tagged-value contents are deliberately omitted.
"""

import argparse
import contextlib
import io
import json
import re
from pathlib import Path

import tmp.tmp as tmp
from core.dfd_extraction import DFD_extraction
from output_generators import traceability
from technology_specific_extractors.quarkus.qrs_entry import extract as extract_quarkus
from technology_specific_extractors.quarkus.qrs_entry import uncomment, JAVA_TOKEN

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
    # Legacy grep evidence is a one-based string. Parser ints mix zero- and
    # one-based conventions across modules; preserve the file with unknown line.
    if isinstance(value, str) and value.isdecimal():
        line = int(value)
    elif type(value) is int and value >= 0:
        return path.as_posix(), None
    else:
        return None, None
    return path.as_posix(), line


def apply_bindings(root, nodes, flows, coverage, evidence):
    """Apply explicit source-owned bindings without interpreting deployment configuration."""
    if (not isinstance(evidence, dict) or set(evidence) != {
            'schema_version', 'context_fingerprint', 'service_roots', 'bindings'}
            or type(evidence['schema_version']) is not int or evidence['schema_version'] != 1
            or not isinstance(evidence['context_fingerprint'], str)
            or not re.fullmatch(r'[a-f0-9]{64}', evidence['context_fingerprint'])
            or not isinstance(evidence['service_roots'], list)
            or not isinstance(evidence['bindings'], list)):
        raise ValueError('Invalid explicit client-binding evidence')
    owners = {}
    for node in nodes:
        owners.setdefault(node.get('root'), []).append(node['name'])
    selected = set()
    for relative in evidence['service_roots']:
        if (not isinstance(relative, str) or Path(relative).is_absolute()
                or '..' in Path(relative).parts
                or not (root / relative).resolve().is_relative_to(root)
                or not (root / relative).is_dir()):
            raise ValueError('Invalid selected service root')
        selected.add(relative)
    selected_nodes = {name for relative in selected for name in owners.get(relative, [])}
    # Default URL heuristics cannot override an explicitly selected deployment.
    flows[:] = [f for f in flows if not (
        f['sender'] in selected_nodes and 'restful_http' in f['stereotypes']
        and not any('message_' in label or 'database' in label or label == 'jdbc'
                    for label in f['stereotypes']))]
    coverage[:] = [c for c in coverage if c['file'] == '.' or not any(
        Path(c['file']).is_relative_to(Path(p)) for p in selected)]
    seen = set()
    for row in evidence['bindings']:
        if not isinstance(row, dict) or set(row) != {
            'source_root', 'destination_root', 'file', 'line', 'destination_kind', 'resolution_detail'}:
            raise ValueError('Invalid explicit binding')
        file = row['file']
        line = row['line']
        source = row['source_root']
        destination = row['destination_root']
        status = row['destination_kind']
        detail = row['resolution_detail']
        if (not isinstance(file, str) or Path(file).is_absolute() or '..' in Path(file).parts
                or not (root / file).resolve().is_relative_to(root)
                or not (root / file).is_file() or Path(file).suffix != '.java'
                or type(line) is not int or line < 1
                or not isinstance(source, str) or source not in selected
                or status not in {'internal', 'external', 'unknown'}
                or not isinstance(detail, str) or not detail or '\n' in detail
                or (file, line) in seen):
            raise ValueError('Invalid binding provenance')
        matches = [p for p in selected if Path(file).is_relative_to(Path(p))]
        if not matches or max(matches, key=lambda p: len(Path(p).parts)) != source:
            raise ValueError('Binding file is not owned by selected source')
        code = JAVA_TOKEN.sub(lambda m: re.sub(r'[^\n]', ' ', m[0]),
                              uncomment((root / file).read_text())).splitlines()
        declaration = re.match(
            r'\s*(?P<annotations>(?:@[\w.$]+(?:\([^;{}]*?\))?\s*)+)'
            r'(?:public\s+)?interface\s+[\w$]+\b', '\n'.join(code[line - 1:]))
        if line > len(code) or declaration is None or not re.search(
                r'@(?:[\w$]+\.)*(?:RegisterRestClient|FeignClient)\b', declaration['annotations']):
            raise ValueError('Binding does not identify an annotated source declaration')
        seen.add((file, line))
        if len(owners.get(source, [])) != 1:
            coverage.append({'file': file, 'line': line,
                             'detail': 'Explicit client source has no unique recovered engine node.'})
            continue
        receiver = None
        if status == 'internal':
            if not isinstance(destination, str) or destination not in selected:
                raise ValueError('Internal binding requires a selected destination root')
            if len(owners.get(destination, [])) == 1:
                receiver = owners[destination][0]
            else:
                status = 'unknown'
                detail = 'Explicit destination has no unique recovered engine node.'
        elif destination is not None:
            raise ValueError('External or unknown binding must not name an internal destination')
        flows.append({'sender': owners[source][0], 'receiver': receiver,
                      'stereotypes': ['restful_http', 'maze_annotated_http_client'],
                      'file': file, 'line': line, 'destination_kind': status,
                      'resolution_detail': detail})
        if status != 'internal':
            coverage.append({'file': file, 'line': line, 'detail': detail})
    coverage.append({'file': '.', 'line': 0, 'detail':
        'Explicit deployment bindings replace selected services\' default HTTP heuristics. '
        'Other HTTP mechanisms in those services are not recovered by this binding adapter; '
        'client declarations do not establish invocation reachability.'})


def analyze(root, evidence=None):
    root = root.resolve()
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
    if evidence is not None:
        apply_bindings(root, nodes, result_flows, coverage, evidence)
    coverage.insert(0, {'file': '.', 'line': 0,
                       'detail': 'Code2DFD uses bounded heuristic extraction. '
                                 'Reachability, profiles, serializers and complete framework '
                                 'coverage are not established; Quarkus clients require '
                                 'literal annotations and application.properties bindings.'})
    return {'schema_version': 1, 'engine': 'code2dfd', 'nodes': nodes,
            'flows': result_flows, 'coverage': coverage,
            'context_fingerprint': evidence['context_fingerprint'] if evidence is not None else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True, type=Path)
    parser.add_argument('--client-bindings', type=Path)
    args = parser.parse_args()
    evidence = json.loads(args.client_bindings.read_text()) if args.client_bindings else None
    print(json.dumps(analyze(args.target.resolve(), evidence), sort_keys=True))


if __name__ == '__main__':
    main()
