"""Execute the real extraction pipeline on isolated Java source snapshots."""

import hashlib
import tempfile
import unittest
from pathlib import Path

from maze_headless import analyze
from maze_headless import apply_bindings, flow_evidence


def service(root, name, framework='quarkus'):
    directory = root / name
    resources = directory / 'src/main/resources'
    resources.mkdir(parents=True)
    (directory / 'src/main/java').mkdir()
    (directory / 'pom.xml').write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        f'<modelVersion>4.0.0</modelVersion><artifactId>{name}</artifactId>'
        '</project>', encoding='utf-8'
    )
    (resources / 'application.properties').write_text(
        f'{framework}.application.name={name}\n', encoding='utf-8'
    )
    return directory


def client(directory, attributes='configKey="peer"'):
    file = directory / 'src/main/java/Peer.java'
    file.write_text(
        'package example;\n'
        'import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;\n'
        f'@RegisterRestClient({attributes})\n'
        'public interface Peer { String get(); }\n', encoding='utf-8'
    )
    return file


class HeadlessTests(unittest.TestCase):
    def test_selected_bindings_preserve_independent_programmatic_http(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            consumer = service(root, 'consumer', 'spring')
            service(root, 'provider', 'spring')
            (consumer / 'src/main/java/Peer.java').write_text(
                'package example;\nimport org.springframework.cloud.openfeign.FeignClient;\n'
                '@FeignClient(name="provider")\npublic interface Peer {}\n')
            (consumer / 'src/main/java/Caller.java').write_text(
                'package example;\nimport org.springframework.web.client.RestTemplate;\n'
                'class Caller { RestTemplate restTemplate;\n'
                'String call() { return restTemplate.getForObject("http://provider" + "/api/items", String.class); } }\n')
            evidence = {'schema_version': 1, 'context_fingerprint': 'a' * 64,
                        'service_roots': ['consumer', 'provider'], 'bindings': [{
                            'source_root': 'consumer', 'destination_root': None,
                            'file': 'consumer/src/main/java/Peer.java', 'line': 3,
                            'destination_kind': 'external', 'resolution_detail': 'Selected external binding.'}]}
            result = analyze(root, evidence)
            independent = [f for f in result['flows'] if f['origin'] == 'upstream'
                           and f['sender'] == 'consumer' and f['receiver'] == 'provider']
            self.assertEqual(len(independent), 1)
            self.assertEqual(independent[0]['metadata_scope'], 'relationship')
            self.assertEqual([w['file'] for w in independent[0]['locations']],
                             ['consumer/src/main/java/Caller.java'])
            supplied = [f for f in result['flows'] if f['origin'] == 'supplied_binding']
            self.assertEqual(len(supplied), 1)
            self.assertIsNone(supplied[0]['receiver'])

    def test_binding_replacement_preserves_mixed_relationship_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            consumer = service(root, 'consumer', 'spring')
            service(root, 'provider', 'spring')
            peer = consumer / 'src/main/java/Peer.java'
            peer.write_text('package example;\n@FeignClient(name="provider")\ninterface Peer {}\n')
            caller = consumer / 'src/main/java/Caller.java'
            caller.write_text('class Caller {\n void call() {}\n}\n')
            flows = [{'sender': 'consumer', 'receiver': 'provider',
                      'stereotypes': ['restful_http', 'feign_connection'],
                      'origin': 'upstream', 'metadata_scope': 'relationship',
                      'file': 'consumer/src/main/java/Peer.java', 'line': '2',
                      '_traces': [{'file': 'consumer/src/main/java/Peer.java', 'line': '2'},
                                  {'file': 'consumer/src/main/java/Caller.java', 'line': '2'}]}]
            coverage = [{'file': 'consumer/src/main/java/Caller.java', 'line': 2,
                         'detail': 'Independent programmatic limitation.'}]
            evidence = {'schema_version': 1, 'context_fingerprint': 'a' * 64,
                        'service_roots': ['consumer', 'provider'], 'bindings': [{
                            'source_root': 'consumer', 'destination_root': 'provider',
                            'file': 'consumer/src/main/java/Peer.java', 'line': 2,
                            'destination_kind': 'internal', 'resolution_detail': 'Selected binding.'}]}
            apply_bindings(root, [{'root': name, 'name': name} for name in ('consumer', 'provider')],
                           flows, coverage, evidence)
            independent = flow_evidence(next(f for f in flows if f['origin'] == 'upstream'), root)
            self.assertEqual(independent['metadata_scope'], 'relationship')
            self.assertEqual(independent['stereotypes'], ['feign_connection', 'restful_http'])
            self.assertEqual([w['file'] for w in independent['locations']],
                             ['consumer/src/main/java/Caller.java'])
            supplied = flow_evidence(next(f for f in flows if f['origin'] == 'supplied_binding'), root)
            self.assertEqual(supplied['metadata_scope'], 'declaration')
            self.assertNotIn('feign_connection', supplied['stereotypes'])
            self.assertIn({'file': 'consumer/src/main/java/Caller.java', 'line': 2,
                           'detail': 'Independent programmatic limitation.'}, coverage)

    def test_explicit_context_overrides_defaults_for_spring_and_quarkus(self):
        for framework in ('spring', 'quarkus'):
            with self.subTest(framework=framework), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                consumer = service(root, 'consumer', framework)
                service(root, 'provider')
                if framework == 'quarkus':
                    file = client(consumer)
                    file.write_text(file.read_text().replace('@RegisterRestClient', '@jakarta.ws.rs.Path("/api")\n@RegisterRestClient'))
                else:
                    (consumer / 'src/main/java/Peer.java').write_text(
                        'package example;\nimport org.springframework.cloud.openfeign.FeignClient;\n'
                        '@FeignClient(name="provider")\npublic interface Peer {}\n')
                evidence = {'schema_version': 1, 'context_fingerprint': 'a' * 64,
                            'service_roots': ['consumer', 'provider'], 'bindings': [{
                                'source_root': 'consumer', 'destination_root': 'provider',
                                'file': 'consumer/src/main/java/Peer.java', 'line': 3,
                                'destination_kind': 'internal', 'resolution_detail': 'Selected binding.'}]}
                result = analyze(root, evidence)
                flows = [f for f in result['flows'] if 'restful_http' in f['stereotypes']]
                self.assertEqual(len(flows), 1)
                self.assertEqual(flows[0]['receiver'], 'provider')
                self.assertEqual(result['context_fingerprint'], 'a' * 64)
                for status in ('external', 'unknown'):
                    evidence['bindings'][0].update(destination_root=None, destination_kind=status)
                    result = analyze(root, evidence)
                    self.assertTrue(all(f['receiver'] is None for f in result['flows']
                                        if 'restful_http' in f['stereotypes']))
                    self.assertTrue(any(c['detail'] == 'Selected binding.'
                                        for c in result['coverage']))

    def test_explicit_binding_boundary_rejects_forged_locations(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            consumer = service(root, 'consumer')
            client(consumer)
            evidence = {'schema_version': 1, 'context_fingerprint': 'a' * 64,
                        'service_roots': ['consumer'], 'bindings': [{
                            'source_root': 'consumer', 'destination_root': None,
                            'file': 'consumer/src/main/java/Peer.java', 'line': 1,
                            'destination_kind': 'unknown', 'resolution_detail': 'Unknown binding.'}]}
            for file, line in (('../outside.java', 3), ('consumer/src/main/java/Peer.java', 1),
                               ('consumer/src/main/java/Peer.java', True)):
                evidence['bindings'][0].update(file=file, line=line)
                with self.assertRaises(ValueError):
                    apply_bindings(root, [{'root': 'consumer', 'name': 'consumer'}], [], [], evidence)

    def test_quarkus_and_spring_extraction_preserve_snapshot(self):
        with tempfile.TemporaryDirectory(prefix='code2dfd-latest-') as temporary:
            root = Path(temporary)
            consumer = service(root, 'consumer')
            service(root, 'provider')
            spring = service(root, 'spring', 'spring')
            client(consumer)
            configuration = consumer / 'src/main/resources/application.properties'
            configuration.write_text(configuration.read_text() +
                                     'quarkus.rest-client.peer.url=http://provider:8080\n')
            (spring / 'src/main/java/Peer.java').write_text(
                '@FeignClient(name = "provider")\npublic interface Peer {}\n'
            )
            excluded = consumer / 'src/test/java/Peer.java'
            excluded.parent.mkdir(parents=True)
            excluded.write_text('@RegisterRestClient(baseUri="http://spring") interface Peer {}')
            sentinel = root / 'application-started'
            (root / 'start.py').write_text(f'open({str(sentinel)!r}, "w").write("executed")')
            before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in root.rglob('*') if p.is_file()}
            result = analyze(root)
            pairs = {(f['sender'], f['receiver']) for f in result['flows']}
            self.assertIn(('consumer', 'provider'), pairs)
            self.assertIn(('spring', 'provider'), pairs)
            self.assertNotIn(('consumer', 'spring'), pairs)
            self.assertEqual(next(f for f in result['flows']
                                  if 'quarkus_rest_client' in f['stereotypes'])['line'], 3)
            self.assertFalse(sentinel.exists())
            self.assertEqual(before, {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                                      for p in root.rglob('*') if p.is_file()})

    def test_effective_configuration_and_unknown_destinations(self):
        cases = [
            ('quarkus.rest-client.peer.url=http://provider\n', 'configKey="peer"', 'provider'),
            ('peer/mp-rest/url=http://provider\n', 'configKey="peer"', 'provider'),
            ('quarkus.rest-client."example.Peer".uri=http://provider\n', '', 'provider'),
            ('', 'baseUri="http://provider"', 'provider'),
            ('', 'baseUri="http://provider" + SUFFIX', None),
            ('quarkus.rest-client.peer.url=http://provider\n',
             'configKey="peer" + SUFFIX', None),
            ('quarkus.rest-client.peer.url=http://outside\n',
             'configKey="peer", baseUri="http://provider"', None),
            ('quarkus.rest-client.peer.url=${PEER_URL}\n', 'configKey="peer"', None),
            ('%prod.quarkus.rest-client.peer.url=http://provider\n', 'configKey="peer"', None),
            ('quarkus.rest-client.peer.url=http://provider\n'
             'quarkus.rest-client.peer.url=http://other\n', 'configKey="peer"', None),
        ]
        for config, attributes, expected in cases:
            with self.subTest(config=config), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                consumer = service(root, 'consumer')
                service(root, 'provider')
                client(consumer, attributes)
                configuration = consumer / 'src/main/resources/application.properties'
                configuration.write_text(configuration.read_text() + config)
                result = analyze(root)
                flows = [f for f in result['flows'] if 'quarkus_rest_client' in f['stereotypes']]
                self.assertEqual(len(flows), 1)
                self.assertEqual(flows[0]['receiver'], expected)
                if expected is None:
                    self.assertTrue(any(c['file'].endswith('Peer.java') for c in result['coverage']))

    def test_annotations_inside_java_examples_do_not_create_quarkus_dependencies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            consumer = service(root, 'consumer')
            service(root, 'provider')
            (consumer / 'src/main/java/Example.java').write_text(
                'package example;\n'
                'import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;\n'
                'public class Example {\n'
                'String example = """\n'
                '@RegisterRestClient(baseUri="http://provider")\n'
                'public interface Fake {}\n'
                '""";\n'
                '// @RegisterRestClient(baseUri="http://provider") interface Comment {}\n'
                '}\n'
            )
            result = analyze(root)
            self.assertFalse(any('quarkus_rest_client' in f['stereotypes']
                                 for f in result['flows']))

    def test_feign_placeholder_does_not_crash_and_exports_no_config_secrets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            consumer = service(root, 'consumer', 'spring')
            (consumer / 'src/main/java/Peer.java').write_text(
                '@FeignClient(name="${provider.url}") interface Peer {}\n'
            )
            configuration = consumer / 'src/main/resources/application.properties'
            configuration.write_text(configuration.read_text() +
                                     'spring.datasource.password=very-private-secret\n')
            result = analyze(root)
            self.assertNotIn('very-private-secret', str(result))
            self.assertTrue(result['coverage'])

    def test_explicit_feign_url_does_not_bind_external_host_by_substring(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            consumer = service(root, 'consumer', 'spring')
            service(root, 'provider', 'spring')
            (consumer / 'src/main/java/Peer.java').write_text(
                '@FeignClient(name="provider", url="http://provider.example.invalid")\n'
                'public interface Peer {}\n'
            )
            result = analyze(root)
            self.assertNotIn(('consumer', 'provider'),
                             {(f['sender'], f['receiver']) for f in result['flows']})


if __name__ == '__main__':
    unittest.main()
