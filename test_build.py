import base64
import tempfile
import unittest
from pathlib import Path
from urllib.parse import unquote

from build import Candidate, Result, candidates, choose, parse_trace, provider_files, publish, wifi_pool


def b64(text):
    return base64.b64encode(text.encode()).decode()


class SubscriptionTests(unittest.TestCase):
    def test_wifi_pool_keeps_only_measured_nodes_and_can_recheck_last_publication(self):
        first = 'trojan://first@example.com:443'
        previous = 'trojan://previous@example.net:443'
        unmeasured = 'trojan://unknown@example.org:443'
        measured = candidates([first, previous])
        delays = {measured[0].name: 105, measured[1].name: 50}
        current = candidates([first, unmeasured])
        result = wifi_pool(current, previous, delays)
        self.assertEqual([item.uri for item in result], [previous, first])

    def test_deduplicates_labels_and_parameter_order_across_formats(self):
        first = 'vless://example@example.com:443?type=tcp&security=tls#first'
        duplicate = 'vless://example@example.com:443?security=tls&type=tcp#other'
        nodes = candidates([first, b64(duplicate)])
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0].uri, first)

    def test_preserves_duplicate_option_order_in_proxy_identity(self):
        base = 'vless://example@example.com:443?'
        nodes = candidates([base + 'type=ws&type=grpc', base + 'type=grpc&type=ws'])
        self.assertEqual(len(nodes), 2)

    def test_rejects_local_destinations_and_unrecognized_input(self):
        vmess = b64('{"ps":"local","add":"::1","port":"443"}')
        lines = f'trojan://key@127.0.0.1:443\nvmess://{vmess}\nsocks://key@box.local:1080\nhttps://example.com/'
        self.assertEqual(candidates([lines]), [])

    def test_a_bad_config_cannot_poison_another_proxy_in_the_provider_parser(self):
        nodes = [
            Candidate('valid', 'vless://user@example.com:443'),
            Candidate('invalid', 'ss://unknown:password@example.com:443'),
        ]
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            providers = provider_files(home, nodes)
            self.assertEqual(set(providers), {'valid', 'invalid'})
            valid_feed = home / providers['valid']['path']
            self.assertEqual(valid_feed.read_text(encoding='utf-8'), 'vless://user@example.com:443#valid\n')

    def test_trace_requires_valid_country_and_public_nonbaseline_ip(self):
        self.assertEqual(parse_trace('ip=1.1.1.1\nloc=AU\n', '8.8.8.8'), ('1.1.1.1', 'AU'))
        self.assertIsNone(parse_trace('ip=8.8.8.8\nloc=US\n', '8.8.8.8'))
        self.assertIsNone(parse_trace('ip=192.168.0.1\nloc=AU\n'))
        self.assertIsNone(parse_trace('ip=1.1.1.1\nloc=XX\n'))

    def test_selection_prefers_latency_even_when_fastest_are_in_the_same_country(self):
        nodes = [
            Result(Candidate('a', 'vless://a'), 50, '1.1.1.1', 'DE'),
            Result(Candidate('b', 'vless://b'), 60, '1.1.1.1', 'DE'),
            Result(Candidate('c', 'vless://c'), 70, '8.8.8.8', 'DE'),
            Result(Candidate('d', 'vless://d'), 100, '9.9.9.9', 'NL'),
        ]
        self.assertEqual([result.node.name for result in choose(nodes, 2)], ['a', 'b'])

    def test_malformed_vmess_values_and_dns_labels_do_not_reject_good_entries(self):
        bad_port = b64('{"add":"example.com","port":1e999}')
        bad_text = b64(r'{"add":"example.com","port":443,"path":"\udc00"}')
        long_label = 'a' * 64 + '.example.com'
        good = 'vless://example@example.com:443'
        feed = f'vmess://{bad_port}\nvmess://{bad_text}\ntrojan://k@{long_label}:443\n{good}'
        self.assertEqual([node.uri for node in candidates([feed])], [good])

    def test_happ_exports_country_label_and_keeps_previous_file_on_failure(self):
        result = Result(Candidate('abc123456789', 'trojan://sample@example.com:443#old'), 80, '1.1.1.1', 'DE')
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            publish(output, [result], {})
            feed = (output / 'happ.txt').read_text(encoding='utf-8')
            self.assertNotIn('#profile-update-interval:', feed)
            self.assertIn('trojan://sample@example.com:443#DE · abc123', unquote(feed))
            with self.assertRaises(ValueError):
                publish(output, [], {})
            self.assertEqual((output / 'happ.txt').read_text(encoding='utf-8'), feed)


if __name__ == '__main__':
    unittest.main()
