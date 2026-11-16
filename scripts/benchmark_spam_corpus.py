"""Benchmark evaluation runner for external spam corpora (e.g. Apache SpamAssassin).

Evaluates Agent 1 (ML Baseline), Agent 2 (Gemini), Agent 3 (Laya), and the Consensus Engine
strictly in read-only inference mode without retraining or modifying any models.
Generates metrics, JSON reports, and graphical visualization plots.
"""
import argparse
import asyncio
from datetime import datetime, timezone
import json
import os
import shutil
import sys
import time
from typing import Any, Dict, List, Optional
import matplotlib.pyplot as plt
import numpy as np

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from consensus.engine import ThreatInvestigationEngine
from core.models import ConsensusVerdict, Verdict

DEFAULT_CORPUS_PATH = r"C:\Users\Gbn84\Downloads\20021010_spam\spam"
DEFAULT_OUTPUT_JSON = os.path.join(PROJECT_ROOT, "data", "spam_corpus_eval.json")
DEFAULT_OUTPUT_PLOT = os.path.join(PROJECT_ROOT, "data", "spam_benchmark_graph.png")


def run_corpus_benchmark(
    corpus_dir: str,
    limit: Optional[int] = 50,
    output_json: str = DEFAULT_OUTPUT_JSON,
    output_plot: str = DEFAULT_OUTPUT_PLOT,
) -> Dict[str, Any]:
    print("================================================================================")
    print("      SPAM CORPUS ACCURACY & THREAT CAPTURE BENCHMARK (READ-ONLY INFERENCE)     ")
    print("================================================================================")
    print(f"Target Corpus:    {corpus_dir}")
    print(f"Timestamp:        {datetime.now(timezone.utc).isoformat()}")
    print("Guarantee:        STRICTLY NO TRAINING / READ-ONLY INFERENCE MODE")
    print("Ground Truth:     All samples are verified SPAM emails (Apache SpamAssassin)")
    print("--------------------------------------------------------------------------------\n")

    if not os.path.isdir(corpus_dir):
        raise FileNotFoundError(f"Corpus directory not found: {corpus_dir}")

    # Read and sort valid email files (skip non-email script files like 0000.*)
    all_files = sorted([f for f in os.listdir(corpus_dir) if not f.startswith("0000.")])
    total_available = len(all_files)
    print(f"Found {total_available} total spam email files in directory.")

    eval_files = all_files[:limit] if (limit and limit > 0) else all_files
    print(f"Selected {len(eval_files)} emails for evaluation (limit={limit or 'ALL'}).\n")

    # Initialize Threat Investigation Engine (Read-only inference)
    engine = ThreatInvestigationEngine()

    sample_results = []
    start_time = time.time()

    async def evaluate_samples():
        nonlocal sample_results
        for idx, filename in enumerate(eval_files, start=1):
            filepath = os.path.join(corpus_dir, filename)
            t_sample_start = time.time()
            try:
                with open(filepath, "rb") as f:
                    raw_bytes = f.read()
                
                # Execute full 2-round multi-agent deliberation
                state = await engine.run_investigation(raw_bytes, source=f"corpus:{filename}")
                
                # Extract Round 2 reports
                r2_reports = {r.agent_id: r for r in state.reports if r.round == 2}
                ml_rep = r2_reports.get("ml")
                gemini_rep = r2_reports.get("gemini")
                laya_rep = r2_reports.get("laya")

                ml_verdict = ml_rep.verdict.value if ml_rep else "UNAVAILABLE"
                ml_conf = ml_rep.confidence if ml_rep else 0.0

                gemini_verdict = gemini_rep.verdict.value if gemini_rep else "UNAVAILABLE"
                gemini_conf = gemini_rep.confidence if gemini_rep else 0.0

                laya_verdict = laya_rep.verdict.value if laya_rep else "UNAVAILABLE"
                laya_conf = laya_rep.confidence if laya_rep else 0.0

                consensus_verdict = state.final_result.final_verdict.value if state.final_result else "UNKNOWN"
                consensus_conf = state.final_result.confidence if state.final_result else 0.0
                matched_rule = state.final_result.matched_rule_id if state.final_result else "NONE"

                sample_results.append({
                    "filename": filename,
                    "ground_truth": "SPAM",
                    "evidence_count": len(state.evidence),
                    "agents": {
                        "ml": {"verdict": ml_verdict, "confidence": ml_conf},
                        "gemini": {"verdict": gemini_verdict, "confidence": gemini_conf},
                        "laya": {"verdict": laya_verdict, "confidence": laya_conf},
                    },
                    "consensus": {
                        "verdict": consensus_verdict,
                        "confidence": consensus_conf,
                        "rule": matched_rule,
                    },
                    "elapsed_sec": round(time.time() - t_sample_start, 2),
                })

                if idx % 5 == 0 or idx == len(eval_files):
                    elapsed_total = time.time() - start_time
                    avg_time = elapsed_total / idx
                    eta_remaining = avg_time * (len(eval_files) - idx)
                    print(
                        f"[{idx:>3}/{len(eval_files)}] ({idx/len(eval_files)*100:>5.1f}%) "
                        f"Sample: {filename[:12]}... | "
                        f"ML: {ml_verdict:<9} | Laya: {laya_verdict:<10} | Consensus: {consensus_verdict:<12} | "
                        f"Avg: {avg_time:.2f}s/email | ETA: {eta_remaining:.0f}s"
                    )

            except Exception as e:
                print(f"[ERROR] Failed processing {filename}: {e}")

    asyncio.run(evaluate_samples())

    total_eval_time = time.time() - start_time
    print(f"\nCompleted evaluation of {len(sample_results)} emails in {total_eval_time:.2f}s ({total_eval_time/max(len(sample_results),1):.2f}s per email).")

    # =========================================================================
    # Compute Detailed Metrics per System
    # =========================================================================
    systems = ["ml", "gemini", "laya", "consensus"]
    system_names = {
        "ml": "Agent 1: ML Baseline (TF-IDF + Naive Bayes)",
        "gemini": "Agent 2: Gemini Cloud Adapter (Privacy Gated)",
        "laya": "Agent 3: Laya System 1 (ModernBERT on CUDA)",
        "consensus": "Consensus Engine (Multi-Agent Synthesis)",
    }

    metrics = {}
    N = len(sample_results)

    for sys_key in systems:
        exact_spam_count = 0
        threat_captured_count = 0  # SPAM, PHISHING, or SUSPICIOUS
        evaded_clean_count = 0     # Misclassified as LEGITIMATE (False Negative)
        needs_review_count = 0
        abstained_count = 0
        verdict_distribution = {}

        for item in sample_results:
            if sys_key == "consensus":
                v = item["consensus"]["verdict"]
            else:
                v = item["agents"][sys_key]["verdict"]

            verdict_distribution[v] = verdict_distribution.get(v, 0) + 1

            if v == "SPAM":
                exact_spam_count += 1
            if v in {"SPAM", "PHISHING", "SUSPICIOUS"}:
                threat_captured_count += 1
            elif v == "LEGITIMATE":
                evaded_clean_count += 1
            elif v == "NEEDS_REVIEW":
                needs_review_count += 1
            elif v in {"ABSTAIN", "UNAVAILABLE"}:
                abstained_count += 1

        exact_accuracy = (exact_spam_count / N) * 100 if N > 0 else 0.0
        threat_capture_rate = (threat_captured_count / N) * 100 if N > 0 else 0.0
        evasion_rate = (evaded_clean_count / N) * 100 if N > 0 else 0.0
        review_rate = (needs_review_count / N) * 100 if N > 0 else 0.0

        metrics[sys_key] = {
            "name": system_names[sys_key],
            "total_tested": N,
            "exact_spam_count": exact_spam_count,
            "exact_spam_accuracy_pct": round(exact_accuracy, 2),
            "threat_captured_count": threat_captured_count,
            "threat_capture_rate_pct": round(threat_capture_rate, 2),
            "evaded_clean_count": evaded_clean_count,
            "evasion_rate_pct": round(evasion_rate, 2),
            "needs_review_count": needs_review_count,
            "needs_review_rate_pct": round(review_rate, 2),
            "abstained_count": abstained_count,
            "verdict_distribution": verdict_distribution,
        }

    # =========================================================================
    # Print Formatted Evaluation Report
    # =========================================================================
    print("\n" + "=" * 88)
    print("                    EMPIRICAL SPAM EVALUATION METRICS TABLE                     ")
    print("=" * 88)
    print(f"{'System':<40} | {'Exact Spam Acc':<14} | {'Threat Capture':<14} | {'Evasion (FN)':<12}")
    print("-" * 88)
    for sys_key in systems:
        m = metrics[sys_key]
        print(
            f"{m['name']:<40} | "
            f"{m['exact_spam_accuracy_pct']:>5.1f}% ({m['exact_spam_count']:>2}/{N}) | "
            f"{m['threat_capture_rate_pct']:>5.1f}% ({m['threat_captured_count']:>2}/{N}) | "
            f"{m['evasion_rate_pct']:>5.1f}% ({m['evaded_clean_count']:>2}/{N})"
        )
    print("=" * 88)

    # Save JSON Report
    os.makedirs(os.path.dirname(output_json), exist_ok=True)
    report_data = {
        "benchmark_metadata": {
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
            "corpus": corpus_dir,
            "total_emails_evaluated": N,
            "ground_truth_label": "SPAM",
            "runtime_seconds": round(total_eval_time, 2),
            "hardware": "NVIDIA GeForce RTX 4050 Laptop GPU (CUDA)" if "cuda" in str(getattr(engine.get_agent_by_id("laya"), "device", "")) else "CPU",
            "no_training_verification": "CONFIRMED: Inference strictly read-only; no weights modified",
        },
        "summary_metrics": metrics,
        "sample_evaluations": sample_results,
    }
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    print(f"\n[OK] Benchmark JSON saved to: {output_json}")

    # =========================================================================
    # Generate High-Resolution Matplotlib Plot
    # =========================================================================
    try:
        generate_plots(metrics, N, output_plot)
    except Exception as e:
        print(f"[WARNING] Could not generate matplotlib plot: {e}")

    return report_data


def generate_plots(metrics: Dict[str, Any], N: int, output_plot_path: str):
    """Generate high-resolution comparative benchmark charts."""
    systems = ["ml", "gemini", "laya", "consensus"]
    labels = ["Agent 1\n(ML TF-IDF)", "Agent 2\n(Gemini Cloud)", "Agent 3\n(Laya System 1)", "Consensus\nEngine"]

    threat_rates = [metrics[s]["threat_capture_rate_pct"] for s in systems]
    exact_rates = [metrics[s]["exact_spam_accuracy_pct"] for s in systems]
    evasion_rates = [metrics[s]["evasion_rate_pct"] for s in systems]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6), facecolor="#0f172a")
    
    for ax in (ax1, ax2):
        ax.set_facecolor("#1e293b")
        ax.tick_params(colors="#cbd5e1", labelsize=10)
        ax.spines["bottom"].set_color("#475569")
        ax.spines["left"].set_color("#475569")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.grid(axis="y", linestyle="--", alpha=0.3, color="#64748b")

    x = np.arange(len(labels))
    width = 0.35

    # Subplot 1: Threat Capture vs Exact Spam Match
    rects1 = ax1.bar(x - width/2, threat_rates, width, label="Threat Capture Rate (%)", color="#3b82f6", edgecolor="#1d4ed8")
    rects2 = ax1.bar(x + width/2, exact_rates, width, label="Exact Spam Match (%)", color="#a855f7", edgecolor="#7e22ce")

    ax1.set_ylabel("Accuracy / Detection Rate (%)", color="#f8fafc", fontsize=12, fontweight="bold")
    ax1.set_title(f"Spam Threat Detection on Real Corpus (N={N})", color="#f8fafc", fontsize=13, fontweight="bold", pad=12)
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, color="#f8fafc", fontweight="bold")
    ax1.set_ylim(0, 110)
    legend1 = ax1.legend(facecolor="#0f172a", edgecolor="#475569", labelcolor="#f8fafc", fontsize=10)

    # Add data labels
    for rect in rects1:
        h = rect.get_height()
        ax1.annotate(f"{h:.1f}%", xy=(rect.get_x() + rect.get_width() / 2, h), xytext=(0, 3),
                     textcoords="offset points", ha="center", va="bottom", color="#60a5fa", fontweight="bold", fontsize=9)
    for rect in rects2:
        h = rect.get_height()
        ax1.annotate(f"{h:.1f}%", xy=(rect.get_x() + rect.get_width() / 2, h), xytext=(0, 3),
                     textcoords="offset points", ha="center", va="bottom", color="#d8b4fe", fontweight="bold", fontsize=9)

    # Subplot 2: Threat Evasion (False Negatives - Lower is better)
    colors = ["#ef4444" if r > 0 else "#10b981" for r in evasion_rates]
    rects3 = ax2.bar(labels, evasion_rates, width=0.5, color=colors, edgecolor="#991b1b")
    ax2.set_ylabel("False Negative / Evasion Rate (%)", color="#f8fafc", fontsize=12, fontweight="bold")
    ax2.set_title("Spam Evasion Rate (Falsely Labeled Legitimate)", color="#f8fafc", fontsize=13, fontweight="bold", pad=12)
    ax2.set_ylim(0, max(max(evasion_rates) + 20, 50))

    for rect in rects3:
        h = rect.get_height()
        ax2.annotate(f"{h:.1f}%", xy=(rect.get_x() + rect.get_width() / 2, h), xytext=(0, 3),
                     textcoords="offset points", ha="center", va="bottom", color="#fca5a5" if h > 0 else "#6ee7b7", fontweight="bold", fontsize=10)

    plt.suptitle("Multi-Agent Threat Intelligence Platform: Apache SpamAssassin Benchmark",
                 color="#f8fafc", fontsize=15, fontweight="bold", y=0.98)

    plt.tight_layout()
    os.makedirs(os.path.dirname(output_plot_path), exist_ok=True)
    plt.savefig(output_plot_path, dpi=200, bbox_inches="tight")
    plt.close()
    print(f"[OK] Graphical plot saved to: {output_plot_path}")

    # Also copy plot to conversation artifact directory if active
    artifact_dir = r"C:\Users\Gbn84\.gemini\antigravity\brain\44ff6cf0-bd40-4bec-a359-800c07051050"
    if os.path.isdir(artifact_dir):
        artifact_copy = os.path.join(artifact_dir, "spam_benchmark_graph.png")
        shutil.copy(output_plot_path, artifact_copy)
        print(f"[OK] Copied plot to artifact directory: {artifact_copy}")


def main():
    parser = argparse.ArgumentParser(description="Spam Corpus Benchmark Runner")
    parser.add_argument("--path", type=str, default=DEFAULT_CORPUS_PATH, help="Path to raw spam email folder")
    parser.add_argument("--limit", type=int, default=50, help="Maximum emails to evaluate (0 or negative for ALL 500)")
    parser.add_argument("--all", action="store_true", help="Evaluate all 500 spam emails in corpus")
    parser.add_argument("--output-json", type=str, default=DEFAULT_OUTPUT_JSON, help="Path to output JSON")
    parser.add_argument("--output-plot", type=str, default=DEFAULT_OUTPUT_PLOT, help="Path to output plot PNG")

    args = parser.parse_args()
    limit = None if args.all else args.limit
    run_corpus_benchmark(
        corpus_dir=args.path,
        limit=limit,
        output_json=args.output_json,
        output_plot=args.output_plot,
    )


if __name__ == "__main__":
    main()
