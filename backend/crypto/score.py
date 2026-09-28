from typing import List, Dict, Any

class SecurityScoreCalculator:
    """
    Calculates an overall Security Score out of 100 based on findings.
    Score starts at 100 and applies deductive penalties:
    - Critical: -15 pts
    - High:     -8 pts
    - Medium:   -4 pts
    - Low:      -1 pt
    - Info:      0 pts
    """
    @staticmethod
    def calculate(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        score = 100.0
        counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Informational": 0
        }

        category_scores = {
            "Cryptographic Security": 100.0,
            "Permission Security": 100.0,
            "Network Security": 100.0,
            "Storage Security": 100.0,
            "Secrets Exposure": 100.0,
            "Application Configuration": 100.0,
            "Signature Information": 100.0
        }

        penalties = {
            "Critical": 15.0,
            "High": 8.0,
            "Medium": 4.0,
            "Low": 1.0,
            "Informational": 0.0
        }

        for f in findings:
            sev = f.get("severity", "Low")
            counts[sev] = counts.get(sev, 0) + 1
            penalty = penalties.get(sev, 1.0)
            score -= penalty

            cat = f.get("category", "")
            if "Crypto" in cat:
                category_scores["Cryptographic Security"] = max(0.0, category_scores["Cryptographic Security"] - penalty * 1.5)
            elif "Permission" in cat:
                category_scores["Permission Security"] = max(0.0, category_scores["Permission Security"] - penalty * 1.5)
            elif "Network" in cat:
                category_scores["Network Security"] = max(0.0, category_scores["Network Security"] - penalty * 1.5)
            elif "Storage" in cat:
                category_scores["Storage Security"] = max(0.0, category_scores["Storage Security"] - penalty * 1.5)
            elif "Secret" in cat:
                category_scores["Secrets Exposure"] = max(0.0, category_scores["Secrets Exposure"] - penalty * 1.5)
            elif "Config" in cat:
                category_scores["Application Configuration"] = max(0.0, category_scores["Application Configuration"] - penalty * 1.5)

        final_score = max(0, min(100, int(round(score))))
        
        return {
            "security_score": final_score,
            "counts": counts,
            "category_scores": {k: int(round(v)) for k, v in category_scores.items()}
        }
