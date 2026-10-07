#!/usr/bin/python3

"""Human-readable rendering of a classification result for incident response."""

LOW_CONFIDENCE_SCORE = 0.2


def render_classification(result: dict) -> str:
    """Format a Classifier.classify() result as a plain-text investigation report."""
    lines = []
    sep = "=" * 70
    lines.append(sep)
    lines.append(f"  MALWARE FAMILY ATTRIBUTION REPORT")
    lines.append(sep)
    lines.append(f"  Sample            : {result.get('query', '<query>')}")

    family = result["predicted_family"] or "UNKNOWN"
    lines.append(f"  Predicted family  : {family}")
    lines.append(f"  Confidence        : {result['confidence'] * 100:.1f}%  (family vote share among neighbors)")
    lines.append(f"  Best match score  : {result['best_score']:.3f}  (Jaccard, 1.0 = identical features)")
    lines.append("-" * 70)
    lines.append(f"  {'Nearest neighbors':<40}{'family':<16}{'score':>8}")
    lines.append("-" * 70)

    for nb in result["neighbors"]:
        lines.append(f"  {nb['name'][:38]:<40}{nb['family'][:14]:<16}{nb['score']:>8.3f}")

    lines.append(sep)
    if result["best_score"] < LOW_CONFIDENCE_SCORE:
        lines.append("  [!] Low similarity to the known corpus: possible UNKNOWN / NEW family.")
        lines.append("      Treat the predicted family as a weak hint, not an attribution.")
        lines.append(sep)

    return "\n".join(lines)
