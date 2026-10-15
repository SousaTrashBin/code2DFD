"""Extract possible REST-client dependencies from explicit default configuration.

This adds framework facts to Code2DFD; it does not establish invocation reachability,
payload compatibility, active profiles or runtime configuration. Configuration
values and credentials never leave this module.
"""

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

import core.file_interaction as fi

REGISTER = re.compile(
    r'@(?:org\.eclipse\.microprofile\.rest\.client\.inject\.)?RegisterRestClient'
    r'\b(?:\s*\(([^)]*)\))?'
)
JAVA_TOKEN = re.compile(
    r'"""(?:\\.|(?!""").)*"""|"(?:\\.|[^"\\])*"'
    r'|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*.*?\*/', re.S
)


def uncomment(text):
    return JAVA_TOKEN.sub(
        lambda match: re.sub(r'[^\n]', ' ', match[0])
        if match[0].startswith(('//', '/*')) else match[0], text
    )


def properties(root, service_root, service_roots):
    values, profiled = {}, set()
    for path in fi.source_files():
        relative = path.relative_to(root)
        owners = [p for p in service_roots if relative.is_relative_to(p)]
        if not owners or max(owners, key=lambda p: len(p.parts)) != service_root:
            continue
        if path.name != 'application.properties':
            continue
        for line in path.read_text(encoding='utf-8').splitlines():
            if line.lstrip().startswith(('#', '!')):
                continue
            match = re.fullmatch(r'\s*([^:=\s]+)\s*[:=]\s*(.*?)\s*', line)
            if match:
                key, value = match.groups()
                key = key.replace('"', '')
                if key.startswith('%') and '.' in key:
                    profiled.add(key.split('.', 1)[1])
                else:
                    values.setdefault(key, set()).add(value)
    return values, profiled


def extract(root, nodes):
    roots = [Path(n['root']) for n in nodes if n.get('root') is not None]
    flows, coverage = [], []
    for path in fi.source_files():
        if path.suffix != '.java':
            continue
        relative = path.relative_to(root)
        text = uncomment(path.read_text(encoding='utf-8'))
        # Keep annotation values in text, but use lexical positions to reject
        # declarations/imports/type names embedded in strings and text blocks.
        code = JAVA_TOKEN.sub(lambda match: re.sub(r'[^\n]', ' ', match[0]), text)
        registrations = [match for match in REGISTER.finditer(text)
                         if code[match.start()] == '@']
        if not registrations:
            continue
        if ('import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;' not in code
                and '@org.eclipse.microprofile.rest.client.inject.RegisterRestClient' not in code):
            continue
        owners = [p for p in roots if relative.is_relative_to(p)]
        if not owners:
            coverage.append({'file': relative.as_posix(), 'line': 1,
                             'detail': 'REST client has no recovered service root.'})
            continue
        service_root = max(owners, key=lambda p: len(p.parts))
        sources = [n['name'] for n in nodes if n.get('root') == service_root.as_posix()]
        if len(sources) != 1:
            coverage.append({'file': relative.as_posix(), 'line': 1,
                             'detail': 'REST client service root is ambiguous.'})
            continue
        source = sources[0]
        config, profiled = properties(root, service_root, roots)
        for registration in registrations:
            line = text.count('\n', 0, registration.start()) + 1
            attributes = registration[1] or ''
            declaration = re.match(r'\s*(?:@[\w.]+(?:\([^)]*\))?\s*)*'
                                   r'(?:public\s+)?interface\s+(\w+)',
                                   code[registration.end():])
            unsupported = len(registrations) != 1 or declaration is None
            package = re.search(r'\bpackage\s+([\w.]+)\s*;', code)
            interface = declaration[1] if declaration else ''
            fqn = (package[1] + '.' if package else '') + interface
            key_match = re.search(r'\bconfigKey\s*=\s*("(?:\\.|[^"\\])*")\s*(?=,|$)',
                                  attributes)
            key = json.loads(key_match[1]) if key_match else fqn
            if 'configKey' in attributes and key_match is None:
                unsupported = True
            keys = [f'quarkus.rest-client.{key}.{suffix}' for suffix in ('url', 'uri')]
            keys += [f'{key}/mp-rest/{suffix}' for suffix in ('url', 'uri')]
            candidates = set().union(*(config.get(k, set()) for k in keys))
            if any(k in profiled for k in keys):
                unsupported = True
            if not candidates:
                base = re.search(r'\bbaseUri\s*=\s*("(?:\\.|[^"\\])*")\s*(?=,|$)',
                                 attributes)
                if base:
                    candidates.add(json.loads(base[1]))
            receiver = None
            if len(candidates) == 1 and not unsupported:
                url = next(iter(candidates))
                if '$' not in url and '{' not in url and '}' not in url:
                    parsed = urlsplit(url)
                    if parsed.scheme in ('http', 'https'):
                        matches = [n['name'] for n in nodes
                                   if n['name'].removeprefix('pom_').casefold()
                                   == (parsed.hostname or '').casefold()]
                        if len(matches) == 1:
                            receiver = matches[0]
            flows.append({'sender': source, 'receiver': receiver,
                          'stereotypes': ['restful_http', 'quarkus_rest_client'],
                          'file': relative.as_posix(), 'line': line})
            if receiver is None:
                coverage.append({'file': relative.as_posix(), 'line': line,
                                 'detail': 'REST client destination is dynamic, external, '
                                           'profile-dependent, ambiguous or unsupported.'})
    return flows, coverage
