"""Regression checks for duplicate metadata and source witness integrity."""
import unittest

from core.dfd_extraction import merge_duplicate_annotations, merge_duplicate_flows, merge_duplicate_nodes
from output_generators import traceability as trace


class MergeTests(unittest.TestCase):
    def test_three_parallel_flows_merge_each_annotation_once(self):
        flows = {i: {'sender': 'A', 'receiver': 'B', 'stereotype_instances': ['restful_http'],
                     'tagged_values': container([('Marker', str(i))])}
                 for i, container in enumerate((set, list, tuple))}
        merge_duplicate_flows(flows)
        self.assertEqual(len(flows), 1)
        self.assertEqual(len(flows[0]['tagged_values']), 3)
        merge_duplicate_annotations(flows)
        self.assertEqual(set(flows[0]['tagged_values']), {('Marker', '0'), ('Marker', '1'), ('Marker', '2')})

    def test_missing_and_null_metadata_remain_distinct(self):
        for value in (None, []):
            flows = {0: {'sender': 'a', 'receiver': 'b'},
                     1: {'sender': 'a', 'receiver': 'b', 'tagged_values': value}}
            merge_duplicate_flows(flows)
            merge_duplicate_annotations(flows)
            self.assertEqual(flows[0]['tagged_values'], value)
        flows = {0: {'sender': 'a', 'receiver': 'b', 'tagged_values': None},
                 1: {'sender': 'a', 'receiver': 'b', 'tagged_values': {('Marker', 'known')}}}
        merge_duplicate_flows(flows)
        self.assertEqual(flows[0]['tagged_values'], [('Marker', 'known')])
        self.assertIn('tagged_values', flows[0]['unknown_metadata'])

    def test_malformed_metadata_fails_without_values(self):
        for value in ('private-secret', {'Password': 'private-secret'}, True):
            flows = {0: {'sender': 'a', 'receiver': 'b', 'tagged_values': value}}
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(ValueError) as error:
                    merge_duplicate_flows(flows)
                self.assertNotIn('private-secret', str(error.exception))

    def test_duplicate_nodes_preserve_metadata_and_scalar_paths(self):
        nodes = {i: {'name': 'A', 'type': 'service', 'pom_path': 'a/pom.xml',
                     'tagged_values': {('Marker', str(i))}} for i in range(3)}
        merge_duplicate_nodes(nodes)
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]['pom_path'], 'a/pom.xml')
        self.assertEqual(len(nodes[0]['tagged_values']), 3)

    def test_same_named_services_with_distinct_roots_remain_ambiguous(self):
        nodes = {i: {'name': 'Peer', 'pom_path': f'{i}/pom.xml',
                     'stereotype_instances': ['internal']} for i in range(2)}
        merge_duplicate_nodes(nodes)
        self.assertEqual(len(nodes), 2)
        self.assertEqual({node['pom_path'] for node in nodes.values()}, {'0/pom.xml', '1/pom.xml'})


class TraceTests(unittest.TestCase):
    def setUp(self):
        trace.traceability = {'nodes': {}, 'edges': {}}

    def add(self, file, item='a -> b', parent=None):
        row = {'item': item, 'file': file, 'line': '3', 'span': (0, 5)}
        if parent:
            row['parent_item'] = parent
        trace.add_trace(row)

    def test_repeated_and_reversed_traces_keep_distinct_locations(self):
        self.add('Peer.java')
        self.add('AnotherPeer.java')
        self.add('Peer.java')
        self.add('Reverse.java', 'b -> a')
        trace.revert_flow('a', 'b')
        locations = trace.traceability['edges']['b -> a']['locations']
        self.assertEqual({r['file'] for r in locations}, {'Peer.java', 'AnotherPeer.java', 'Reverse.java'})

    def test_subtrace_repetition_does_not_erase_parent_or_locations(self):
        self.add('Peer.java')
        self.add('Protection.java', 'protection', 'a -> b')
        self.add('Other.java', 'protection', 'a -> b')
        self.add('AnotherPeer.java')
        record = trace.traceability['edges']['a -> b']
        self.assertEqual(len(record['locations']), 2)
        self.assertEqual(len(record['sub_items']['protection']['locations']), 2)

class HeadlessWitnessTests(unittest.TestCase):
    def test_parallel_feign_witnesses_are_deterministic_and_owned(self):
        import hashlib
        import tempfile
        from pathlib import Path
        from maze_headless import analyze
        from test_headless import service
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            consumer = service(root, 'consumer', 'spring')
            service(root, 'provider', 'spring')
            for name in ('Peer', 'Other', 'Third'):
                (consumer / f'src/main/java/{name}.java').write_text(
                    f'@FeignClient(name="provider")\npublic interface {name} {{}}\n')
            before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in root.rglob('*') if p.is_file()}
            first = analyze(root)
            self.assertEqual(first['schema_version'], 2)
            self.assertEqual(first, analyze(root))
            flows = [f for f in first['flows'] if 'restful_http' in f['stereotypes']]
            self.assertEqual(len(flows), 1)
            self.assertEqual(len(flows[0]['locations']), 3)
            self.assertEqual(flows[0]['metadata_scope'], 'relationship')
            self.assertEqual(len({w['evidence_id'] for w in flows[0]['locations']}), 3)
            evidence = {'schema_version': 1, 'context_fingerprint': 'a' * 64,
                        'service_roots': ['consumer', 'provider'], 'bindings': [
                            {'source_root': 'consumer', 'destination_root': 'provider',
                             'file': f'consumer/src/main/java/{name}.java', 'line': 1,
                             'destination_kind': 'internal', 'resolution_detail': 'Selected binding.'}
                            for name in ('Peer', 'Other', 'Third')]}
            selected = analyze(root, evidence)
            flows = [f for f in selected['flows'] if 'restful_http' in f['stereotypes']]
            self.assertEqual(sum(len(f['locations']) for f in flows), 3)
            self.assertTrue(all(f['origin'] == 'supplied_binding' for f in flows))
            self.assertTrue(all(f['metadata_scope'] == 'declaration' for f in flows))
            self.assertEqual(before, {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                                     for p in root.rglob('*') if p.is_file()})

    def test_unresolved_feign_is_retained_without_exporting_values(self):
        import tempfile
        from pathlib import Path
        from maze_headless import analyze
        from test_headless import service
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            consumer = service(root, 'consumer', 'spring')
            (consumer / 'src/main/java/Peer.java').write_text(
                '@FeignClient(name="${private-secret}")\npublic interface Peer {}\n')
            result = analyze(root)
            flows = [f for f in result['flows'] if 'restful_http' in f['stereotypes']]
            self.assertEqual(len(flows), 1)
            self.assertIsNone(flows[0]['receiver'])
            self.assertEqual(flows[0]['destination_kind'], 'unknown')
            self.assertTrue(flows[0]['locations'])
            self.assertNotIn('private-secret', str(result))
            self.assertTrue(any(c['file'].endswith('Peer.java') for c in result['coverage']))
