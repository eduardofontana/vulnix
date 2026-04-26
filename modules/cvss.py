"""
VULNIX - CVSSv3.1 Scoring Module
Common Vulnerability Scoring System v3.1
"""

import math
from typing import Dict, Optional, Tuple


class CVSSv31:
    """Calculate CVSS v3.1 scores."""

    SEVERITY_RANGES = {
        (9.0, 10.0): "CRITICAL",
        (7.0, 8.9): "HIGH",
        (4.0, 6.9): "MEDIUM",
        (0.1, 3.9): "LOW",
        (0.0, 0.0): "NONE",
    }

    VECTOR_METRICS = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
        "AC": {"L": 0.77, "H": 0.44},
        "PR": {"N": {"U": 0.85, "C": 0.85, "H": 0.85}, "L": {"U": 0.62, "C": 0.62, "H": 0.62}, "H": {"U": 0.27, "C": 0.27, "H": 0.27}},
        "UI": {"N": 0.85, "R": 0.62},
        "S": {"U": 0.85, "C": 0.85},
        "C": {"N": 0.0, "L": 0.22, "H": 0.56},
        "I": {"N": 0.0, "L": 0.22, "H": 0.56},
        "A": {"N": 0.0, "L": 0.22, "H": 0.56},
    }

    def __init__(self):
        self.vector_string = ""

    def _roundup(self, value: float) -> float:
        """Round up to nearest 0.1."""
        return math.ceil(value * 10) / 10

    def calculate_base_score(
        self,
        AV: str = "N",
        AC: str = "L",
        PR: str = "N",
        UI: str = "N",
        S: str = "U",
        C: str = "N",
        I: str = "N",
        A: str = "N",
    ) -> Tuple[float, str, str]:
        """Calculate CVSS v3.1 base score."""
        try:
            iss = (1 - ((1 - float(self.VECTOR_METRICS["C"][C])) *
                       (1 - float(self.VECTOR_METRICS["I"][I])) *
                       (1 - float(self.VECTOR_METRICS["A"][A]))))

            if iss == 0:
                return 0.0, "NONE", "NA"

            exploit_sub_m = 0.0
            if PR == "N":
                exploit_sub_m = 0.85
            elif PR == "L":
                exploit_sub_m = 0.62
            elif PR == "H":
                exploit_sub_m = 0.27

            impact_sub_s = min(
                (1 - float(self.VECTOR_METRICS["C"][C]) +
                 1 - float(self.VECTOR_METRICS["I"][I]) +
                 1 - float(self.VECTOR_METRICS["A"][A])),
                1
            ) * (1 if S == "C" else 1)

            if S == "U":
                impact_sub_s = (1 - float(self.VECTOR_METRICS["C"][C]) +
                               1 - float(self.VECTOR_METRICS["I"][I]) +
                               1 - float(self.VECTOR_METRICS["A"][A])) / 3

            impact = 6.42 * impact_sub_s
            exploit = 8.22 * exploit_sub_m * iss

            if impact <= 0:
                base_score = 0.0
            elif exploit <= 0:
                base_score = 6.42 * impact_sub_s
            else:
                base_score = min((impact + exploit), 10)

            base_score = self._roundup(base_score)

            severity = "NONE"
            for (low, high), sev in self.SEVERITY_RANGES.items():
                if low <= base_score <= high:
                    severity = sev
                    break

            return base_score, severity, self._build_vector(
                AV, AC, PR, UI, S, C, I, A
            )

        except (KeyError, ZeroDivisionError):
            return 0.0, "NONE", ""

    def _build_vector(
        self, AV: str, AC: str, PR: str, UI: str,
        S: str, C: str, I: str, A: str
    ) -> str:
        """Build CVSS vector string."""
        self.vector_string = f"CVSS:3.1/AV:{AV}/AC:{AC}/PR:{PR}/UI:{UI}/S:{S}/C:{C}/I:{I}/A:{A}"
        return self.vector_string

    def get_severity_from_score(self, score: float) -> str:
        """Get severity from numeric score."""
        for (low, high), severity in self.SEVERITY_RANGES.items():
            if low <= score <= high:
                return severity
        return "NONE"

    def get_cvss_from_vuln_type(self, vuln_type: str) -> Tuple[float, str]:
        """Estimate CVSS score for vulnerability type."""
        vuln_scores = {
            "sql_injection": (7.5, "HIGH"),
            "xss": (6.1, "MEDIUM"),
            "csrf": (4.3, "LOW"),
            "idor": (6.5, "MEDIUM"),
            "ssrf": (8.6, "HIGH"),
            "open_redirect": (4.3, "LOW"),
            "cors": (6.5, "MEDIUM"),
            "jwt_weak": (6.5, "MEDIUM"),
            "auth_bypass": (8.1, "HIGH"),
            "information_disclosure": (5.3, "MEDIUM"),
            "broken_auth": (7.1, "HIGH"),
            "security_misconfiguration": (4.3, "LOW"),
        }

        return vuln_scores.get(vuln_type, (5.0, "MEDIUM"))

    def calculate_from_finding(
        self, vuln_type: str, impact: str = "low"
    ) -> Dict:
        """Calculate CVSS for a finding."""
        base_score, severity = self.get_cvss_from_vuln_type(vuln_type)

        if impact == "high":
            base_score = min(base_score + 1.5, 10.0)
        elif impact == "low":
            base_score = max(base_score - 1.0, 0.1)

        base_score = round(base_score, 1)
        severity = self.get_severity_from_score(base_score)

        av = "N" if vuln_type in ["ssrf", "sql_injection"] else "A"
        ac = "L" if vuln_type in ["sql_injection", "xss"] else "H"

        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:N/UI:N/S:U/{'C' if impact=='high' else 'N'}/{'I' if impact=='high' else 'N'}/{'A' if impact=='high' else 'N'}"

        return {
            "score": base_score,
            "severity": severity,
            "vector": vector,
        }


class CVSSCalculator:
    """Convenience class for CVSS calculations."""

    def __init__(self):
        self.cvss = CVSSv31()

    def score_finding(self, vuln_type: str, has_poc: bool = False) -> Dict:
        """Score a finding with default assumptions."""
        impact = "high" if has_poc else "low"
        result = self.cvss.calculate_from_finding(vuln_type, impact)
        return result

    def detailed_score(
        self,
        attack_vector: str = "N",
        attack_complexity: str = "L",
        privileges: str = "N",
        user_interaction: str = "N",
        scope: str = "U",
        confidentiality: str = "N",
        integrity: str = "N",
        availability: str = "N",
    ) -> Dict:
        """Calculate detailed CVSS score."""
        score, severity, vector = self.cvss.calculate_base_score(
            AV=attack_vector,
            AC=attack_complexity,
            PR=privileges,
            UI=user_interaction,
            S=scope,
            C=confidentiality,
            I=integrity,
            A=availability,
        )
        return {
            "score": score,
            "severity": severity,
            "vector": vector,
        }