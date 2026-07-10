import unittest

from astral_restoration import (
    AstralNode,
    AstralNodeStatus,
    AstralPlaneRestorer,
    create_default_astral_baseline,
)


class AstralPlaneRestorerTests(unittest.TestCase):
    def test_restores_altered_and_missing_nodes(self):
        baseline = create_default_astral_baseline()
        restorer = AstralPlaneRestorer(baseline)
        current = {node.node_id: node for node in baseline}
        current["lunar_gate"] = AstralNode(
            "lunar_gate", resonance=0.2, alignment="altered", anchors={"rogue"}
        )
        del current["dream_delta"]

        report = restorer.restore(current)

        self.assertEqual(current["lunar_gate"], baseline[1])
        self.assertEqual(current["dream_delta"], baseline[3])
        self.assertEqual(report.restored_nodes, ["lunar_gate"])
        self.assertEqual(report.missing_nodes_recreated, ["dream_delta"])
        self.assertEqual(report.altered_node_count, 2)

    def test_quarantines_unknown_nodes(self):
        restorer = AstralPlaneRestorer(create_default_astral_baseline())
        current = {"rogue_nexus": AstralNode("rogue_nexus", resonance=0.99)}

        report = restorer.restore(current)

        self.assertEqual(report.quarantined_nodes, ["rogue_nexus"])
        self.assertEqual(current["rogue_nexus"].status, AstralNodeStatus.QUARANTINED)
        self.assertEqual(current["rogue_nexus"].resonance, 0.0)

    def test_detects_alterations_without_mutating_current_nodes(self):
        restorer = AstralPlaneRestorer(create_default_astral_baseline())
        current = {
            "astral_root": AstralNode("astral_root", resonance=0.5, alignment="neutral"),
        }

        altered = restorer.detect_alterations(current)

        self.assertIn("astral_root", altered)
        self.assertIn("lunar_gate", altered)
        self.assertEqual(current["astral_root"].resonance, 0.5)


if __name__ == "__main__":
    unittest.main()
