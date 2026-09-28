import os
import json
from typing import List, Dict, Any

class RulesEngine:
    def __init__(self, rules_dir: str = None):
        if not rules_dir:
            rules_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "rules"))
        self.rules_dir = rules_dir
        self.rules_db: Dict[str, Dict[str, Any]] = {}
        self._load_rules()

    def _load_rules(self):
        if not os.path.exists(self.rules_dir):
            return

        for file in os.listdir(self.rules_dir):
            if file.endswith('.json'):
                path = os.path.join(self.rules_dir, file)
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        rules_list = json.load(f)
                        for r in rules_list:
                            self.rules_db[r["id"]] = r
                except Exception:
                    pass

    def enrich_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        rule_id = finding.get("rule_id")
        if rule_id and rule_id in self.rules_db:
            rule = self.rules_db[rule_id]
            finding["reason"] = rule.get("reason", finding.get("description", ""))
            finding["recommendation"] = rule.get("recommendation", "Remediate using standard security best practices.")
            finding["secure_alternative"] = rule.get("secure_alternative", "Modern Secure Alternative")
        else:
            finding["reason"] = finding.get("description", "")
            finding["recommendation"] = "Remediate using standard security best practices."
            finding["secure_alternative"] = "N/A"
        return finding
