from typing import List, Tuple
from ..models.schemas import SecurityFinding, SeverityLevel, AnalysisSummary, ProductionGate

class ScoringEngine:
    WEIGHTS = {
        SeverityLevel.CRITICAL: 2.8,
        SeverityLevel.HIGH: 1.6,
        SeverityLevel.MEDIUM: 0.7,
        SeverityLevel.LOW: 0.2,
        SeverityLevel.INFO: 0.05,
    }

    @classmethod
    def evaluate(cls, findings: List[SecurityFinding], file_type: str, file_name: str) -> Tuple[AnalysisSummary, List[str], str]:
        critical_count = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
        medium_count = sum(1 for f in findings if f.severity == SeverityLevel.MEDIUM)
        low_count = sum(1 for f in findings if f.severity == SeverityLevel.LOW)

        raw_score = 1.0 + sum(cls.WEIGHTS.get(f.severity, 0.1) for f in findings)
        hackability_score = round(min(10.0, max(1.0, raw_score)), 1)

        if critical_count > 0 or hackability_score >= 7.0:
            gate = ProductionGate.BLOCKED
        elif high_count > 0 or hackability_score >= 4.0:
            gate = ProductionGate.NEEDS_HARDENING
        else:
            gate = ProductionGate.READY

        improvements = cls._generate_improvements(findings, file_type)

        if gate == ProductionGate.BLOCKED:
            status_text = "FAILED (Critical vulnerabilities present. Unfit for production deployment)."
        elif gate == ProductionGate.NEEDS_HARDENING:
            status_text = "CONDITIONAL (Hardening required to eliminate moderate-to-high risk vectors)."
        else:
            status_text = "PASSED (Binary adheres to baseline application hardening standards)."

        summary_text = (
            f"Audit for '{file_name}' ({file_type.upper()}) resulted in a Hackability Index of {hackability_score}/10. "
            f"Production Gate: {status_text} "
            f"Detected {critical_count} critical, {high_count} high, and {medium_count} medium severity issues."
        )

        hardening_prompt = (
            f"Act as a Principal Cybersecurity Engineer. Generate an exact, production-ready patch script and configuration diffs "
            f"for '{file_name}' to remediate the following findings:\n"
            + "\n".join(f"- [{f.severity.value}] {f.title}: {f.remediation}" for f in findings)
        )

        summary = AnalysisSummary(
            hackabilityScore=hackability_score,
            productionGate=gate,
            criticalCount=critical_count,
            highCount=high_count,
            mediumCount=medium_count,
            lowCount=low_count,
            totalFindings=len(findings),
            executiveSummary=summary_text
        )

        return summary, improvements, hardening_prompt

    @staticmethod
    def _generate_improvements(findings: List[SecurityFinding], file_type: str) -> List[str]:
        improvements: List[str] = []
        seen = set()

        for f in sorted(findings, key=lambda x: (0 if x.severity == SeverityLevel.CRITICAL else 1 if x.severity == SeverityLevel.HIGH else 2)):
            if f.remediation not in seen:
                improvements.append(f.remediation)
                seen.add(f.remediation)

        if not improvements:
            improvements.append("Integrate automated Static Application Security Testing (SAST) into your CI/CD pipeline.")
            improvements.append("Enforce multi-signature cryptographic verification for release binaries.")

        return improvements[:10]
