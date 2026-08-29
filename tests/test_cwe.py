import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegisguard.catalogs.cwe_definitions import (
    CweKnowledgeEngine,
    CWE_KNOWLEDGE_BASE
)


class TestCweDefinitions(unittest.TestCase):
    def test_catalog_populated(self):
        self.assertGreaterEqual(len(CWE_KNOWLEDGE_BASE), 100)

    def test_get_cwe_lookup(self):
        cwe89 = CweKnowledgeEngine.get_cwe("CWE-89")
        self.assertIsNotNone(cwe89)
        self.assertEqual(cwe89.name, "SQL Injection")
        self.assertIn("cursor.execute", cwe89.secure_code_example)

    def test_search_by_keyword(self):
        results = CweKnowledgeEngine.search("Command Injection")
        self.assertGreater(len(results), 0)

    def test_summary(self):
        summary = CweKnowledgeEngine.get_summary()
        self.assertGreater(summary["total_definitions"], 100)
        self.assertIn("Database Query Construction", summary["domains"])


if __name__ == "__main__":
    unittest.main()
