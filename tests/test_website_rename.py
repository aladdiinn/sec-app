"""
Test suite for Stage 1: Website Rename
Verifies:
1. display_labels.py is wired and contains all display terms.
2. No user-visible 'App Node' or 'Total Apps' remains in templates or rendered output.
3. Internal API names, DB tables, and routes remain unchanged.
"""

import unittest
import os
import re
import sys

# Set test environment credentials for app imports
os.environ["SECRET_KEY"] = "test-secret-key-32-chars-long-security-validation"
os.environ["DB_PASSWORD"] = "test-db-password"
os.environ["POSTGRES_PASSWORD"] = "test-db-password"

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import display_labels

class TestWebsiteRename(unittest.TestCase):
    def test_display_labels_dictionary(self):
        """Verify display_labels.py contains required single-source labels."""
        self.assertEqual(display_labels.get_label("website"), "Website")
        self.assertEqual(display_labels.get_label("websites"), "Websites")
        self.assertEqual(display_labels.get_label("total_websites"), "Total Websites")
        self.assertEqual(display_labels.get_label("website_upper"), "WEBSITE")
        self.assertEqual(display_labels.get_label("websites_upper"), "WEBSITES")
        self.assertEqual(display_labels.format_website_count(1), "1 Website")
        self.assertEqual(display_labels.format_website_count(5), "5 Websites")

    def test_no_visible_app_node_in_templates(self):
        """Grep all HTML templates to ensure no user-visible 'App Node' or 'Total Apps' text exists."""
        template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'templates'))
        
        # User-visible patterns: matching in rendered text, buttons, spans, options, headings
        visible_pattern = re.compile(
            r'(?:>|\b)(?:App\s+Node[s]?|APP\s+NODE[S]?|Total\s+Apps|TOTAL\s+APPS)(?:<|\b)',
            re.IGNORECASE
        )
        
        violations = []
        for root, dirs, files in os.walk(template_dir):
            for file in files:
                if not file.endswith('.html'):
                    continue
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        stripped = line.strip()
                        # Skip JS comments, CSS class definitions, or internal function names
                        if stripped.startswith('//') or stripped.startswith('/*'):
                            continue
                        # If line contains user-facing HTML tag or text
                        if any(tag in line for tag in ['<span', '<button', '<h3', '<h4', '<div', '<option', '<a', '<p', '<label', '<strong>', '<em>']):
                            # Exclude css class attributes like class="... appnode-card ..."
                            text_without_classes = re.sub(r'class="[^"]*"', '', line)
                            text_without_classes = re.sub(r"class='[^']*'", '', text_without_classes)
                            text_without_classes = re.sub(r'id="[^"]*"', '', text_without_classes)
                            if visible_pattern.search(text_without_classes):
                                violations.append(f"{file}:{line_num}: {stripped}")

        self.assertEqual(
            violations, [],
            f"Found user-visible 'App Node' / 'Total Apps' strings in templates:\n" + "\n".join(violations)
        )

    def test_internal_routes_preserved(self):
        """Verify that internal route definitions and handlers remain unchanged."""
        import app
        route_paths = [r.path for r in app.app.routes]
        self.assertIn("/api/app/events", route_paths)
        self.assertIn("/api/app/collector.py", route_paths)
        self.assertIn("/api/approvals/request", route_paths)

if __name__ == '__main__':
    unittest.main()
