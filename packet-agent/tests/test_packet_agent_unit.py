import importlib.util
import time
import unittest
from pathlib import Path


AGENT_FILE = Path(__file__).resolve().parents[1] / 'agent.py'
spec = importlib.util.spec_from_file_location('flex_packet_agent_module', AGENT_FILE)
agent = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(agent)


class PacketAgentUnitTests(unittest.TestCase):
    def test_parse_protocol_port_map(self):
        parsed = agent.parse_protocol_port_map('Modbus/TCP:502, OPC UA:4840, bad, :123, HTTP:80, invalid:x')
        self.assertEqual(parsed[502], 'Modbus/TCP')
        self.assertEqual(parsed[4840], 'OPC UA')
        self.assertEqual(parsed[80], 'HTTP')
        self.assertNotIn('bad', parsed)

    def test_parse_endpoint_protocol_map(self):
        parsed = agent.parse_endpoint_protocol_map('10.0.0.10-10.0.0.20:PROFINET, 10.0.0.1-:X, nope')
        self.assertEqual(parsed[frozenset(('10.0.0.10', '10.0.0.20'))], 'PROFINET')
        self.assertNotIn(frozenset(('10.0.0.1', '')), parsed)

    def test_packet_aggregator_groups_bidir_service_port(self):
        aggregator = agent.PacketAggregator(idle_timeout_seconds=120)

        pkt1 = agent.IP(src='10.0.0.1', dst='10.0.0.2') / agent.TCP(sport=12345, dport=502)
        pkt2 = agent.IP(src='10.0.0.2', dst='10.0.0.1') / agent.TCP(sport=502, dport=12345)
        aggregator.ingest_packet(pkt1)
        aggregator.ingest_packet(pkt2)

        metrics = aggregator.metrics()
        self.assertEqual(metrics['total_packets'], 2)
        self.assertEqual(metrics['active_connections'], 1)

        snapshot = aggregator.snapshot(interval_seconds=1.0)
        self.assertEqual(len(snapshot), 1)
        row = snapshot[0]
        self.assertEqual(row['src_ip'], '10.0.0.1')
        self.assertEqual(row['dst_ip'], '10.0.0.2')
        self.assertEqual(row['protocol'], 'Modbus/TCP')
        self.assertEqual(row['port'], 502)
        self.assertEqual(row['packets'], 2)

    def test_endpoint_protocol_map_overrides_port_inference(self):
        endpoint_map = agent.parse_endpoint_protocol_map('10.0.0.3-10.0.0.4:CustomProto')
        aggregator = agent.PacketAggregator(endpoint_protocol_map=endpoint_map)

        pkt = agent.IP(src='10.0.0.4', dst='10.0.0.3') / agent.TCP(sport=1111, dport=502)
        aggregator.ingest_packet(pkt)
        snapshot = aggregator.snapshot(interval_seconds=1.0)

        self.assertEqual(len(snapshot), 1)
        self.assertEqual(snapshot[0]['protocol'], 'CustomProto')
        self.assertEqual(snapshot[0]['src_ip'], '10.0.0.3')
        self.assertEqual(snapshot[0]['dst_ip'], '10.0.0.4')

    def test_snapshot_eviction_removes_stale(self):
        aggregator = agent.PacketAggregator(idle_timeout_seconds=-1)
        pkt = agent.IP(src='10.0.0.9', dst='10.0.0.8') / agent.UDP(sport=123, dport=53)
        aggregator.ingest_packet(pkt)
        time.sleep(0.001)
        snapshot = aggregator.snapshot(interval_seconds=1.0)
        self.assertEqual(snapshot, [])
        self.assertEqual(aggregator.metrics()['active_connections'], 0)


class ReverseDnsResolverUnitTests(unittest.TestCase):
    def test_is_candidate_filters_loopback_and_multicast(self):
        resolver = agent.ReverseDnsResolver(enabled=True)
        self.assertFalse(resolver._is_candidate('127.0.0.1'))
        self.assertFalse(resolver._is_candidate('224.0.0.1'))
        self.assertTrue(resolver._is_candidate('10.0.0.10'))


if __name__ == '__main__':
    unittest.main()
