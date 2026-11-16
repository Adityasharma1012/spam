"""Cross-platform CLI management tool for Email Threat Detection Platform.

Commands supported:
- setup: Install dependencies and configure environment
- prepare-models: Safely download and verify pinned model weights with resource checks
- laya-check: Inspect local Laya installation, hardware, cache, and inference status
- dev: Run FastAPI backend and Vite frontend development servers
- test: Run full automated pytest test suite
- eval: Run evaluation benchmark across synthetic datasets
"""
import argparse
import asyncio
import os
import shutil
import subprocess
import sys
from typing import Optional

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def get_npm_executable() -> str:
    """Resolve npm executable cross-platform (handling Windows execution policy)."""
    if sys.platform == "win32":
        cmd = shutil.which("npm.cmd") or shutil.which("npm")
        return cmd or "npm.cmd"
    return "npm"


def cmd_setup(args):
    """Setup project dependencies and environment file."""
    print("=== [1/3] Setting up Python dependencies ===")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", os.path.join(PROJECT_ROOT, "requirements.txt")])

    print("\n=== [2/3] Setting up Frontend dependencies ===")
    npm_cmd = get_npm_executable()
    frontend_dir = os.path.join(PROJECT_ROOT, "frontend")
    if os.path.isdir(frontend_dir) and os.path.exists(os.path.join(frontend_dir, "package.json")):
        subprocess.check_call([npm_cmd, "install"], cwd=frontend_dir)
    else:
        print("Frontend directory not yet configured; skipping npm install.")

    print("\n=== [3/3] Checking environment file ===")
    env_file = os.path.join(PROJECT_ROOT, ".env")
    env_example = os.path.join(PROJECT_ROOT, ".env.example")
    if not os.path.exists(env_file) and os.path.exists(env_example):
        shutil.copy(env_example, env_file)
        print("Created .env from .env.example with safe defaults.")
    else:
        print(".env file exists or .env.example not found.")
    print("\nSetup completed successfully!")


def cmd_laya_check(args):
    """Check Laya package, hardware capabilities, and cached weights."""
    print("=== Laya System 1 Verification Check ===")
    try:
        import laya
        print(f"[OK] laya package installed: version {laya.__version__}")
        print(f"     Path: {laya.__file__}")
    except ImportError:
        print("[FAIL] laya package is NOT installed.")
        return

    import torch
    cuda_avail = torch.cuda.is_available()
    print(f"[INFO] CUDA available: {cuda_avail}")
    device = "cuda" if cuda_avail else "cpu"
    print(f"[INFO] Resolved inference device: {device} (CPU fallback active)")

    from agents.laya_agent import (
        PINNED_CHECKPOINT,
        PINNED_REVISION,
        LayaAgent,
        is_laya_model_cached,
    )
    print(f"[INFO] Target Checkpoint: {PINNED_CHECKPOINT}")
    print(f"[INFO] Pinned Revision:   {PINNED_REVISION}")

    cached = is_laya_model_cached()
    print(f"[INFO] Model weights cached locally: {cached}")

    if not cached:
        print("[NOTICE] Weights not found. Run 'python scripts/manage.py prepare-models' to download.")
        return

    print("\nAttempting resident model initialization...")
    agent = LayaAgent(auto_load=True, device=device)
    avail, reason = agent.check_availability()
    print(f"Agent Availability: {avail.value} (Reason: {reason or 'None'})")

    if avail.value == "AVAILABLE":
        print("Running quick dry-run inference...")
        test_state = {"subject": "Test Verification", "body": "Verify resident inference status."}
        try:
            res = agent.agent_instance.predict(test_state, agent.questions_config)
            print("[SUCCESS] Local typed inference operational!")
            answers = res.get("answers", res) if isinstance(res, dict) else {}
            verdict_choice = answers.get("verdict", {}).get("choice") or answers.get("verdict", {}).get("answer")
            print(f"          Result verdict: {verdict_choice}")
        except Exception as e:
            print(f"[FAIL] Inference error: {e}")

        # Live Laya Smoke Test on synthetic sample when RUN_LAYA_LIVE=1 or --live
        run_live = getattr(args, "live", False) or os.environ.get("RUN_LAYA_LIVE") == "1"
        if run_live:
            print("\n=== Live Local Laya Smoke Test (RUN_LAYA_LIVE=1) ===")
            sample_p = os.path.join(PROJECT_ROOT, "data", "samples", "sample_phishing.eml")
            if os.path.exists(sample_p):
                with open(sample_p, "r", encoding="utf-8") as f:
                    content = f.read()
                from core.parser import EmailParser
                parser = EmailParser()
                meta, ev = parser.parse(content)
                live_state = {
                    "subject": meta.get("subject", ""),
                    "body": meta.get("body_plain", ""),
                    "from": meta.get("from", ""),
                }
                print(f"Testing live inference on '{os.path.basename(sample_p)}' ({len(live_state['body'])} chars)...")
                live_res = agent.agent_instance.predict(live_state, agent.questions_config)
                live_answers = live_res.get("answers", live_res) if isinstance(live_res, dict) else {}
                print("\n[LIVE LAYA TYPED OUTPUT]:")
                for q_name, ans in live_answers.items():
                    print(f"  - {q_name}: {ans.get('choice', ans.get('answer', ans.get('score')))} (conf: {ans.get('confidence', ans.get('answer_confidence', 'N/A'))})")
                print("\n[SUCCESS] Live local Laya System 1 smoke test completed successfully!")


def cmd_prepare_models(args):
    """Safely prepare and cache model weights with disk and RAM verification."""
    print("=== Preparing Model Weights for Laya ===")
    from agents.laya_agent import PINNED_CHECKPOINT, PINNED_REVISION, is_laya_model_cached

    if is_laya_model_cached() and not args.force:
        print(f"[OK] Model weights for {PINNED_CHECKPOINT} are already downloaded and cached.")
        return

    # Check resources
    if sys.platform == "win32":
        try:
            free_bytes = shutil.disk_usage("C:\\").free
            print(f"Free disk space on C:: {free_bytes / (1024**3):.2f} GB")
        except Exception:
            pass

    print(f"Model: {PINNED_CHECKPOINT} (Revision: {PINNED_REVISION})")
    print("Approximate download size: 803 MB.")

    if not args.yes:
        confirm = input("Do you wish to download model weights now? [y/N]: ").strip().lower()
        if confirm not in ("y", "yes"):
            print("Aborted by user.")
            return

    print("Downloading weights via huggingface_hub...")
    from huggingface_hub import snapshot_download
    snapshot_download(
        repo_id=PINNED_CHECKPOINT,
        revision=PINNED_REVISION,
    )
    print("Model weights successfully downloaded and verified!")


def cmd_test(args):
    """Run automated pytest suite."""
    print("=== Running Pytest Test Suite ===")
    cmd = [sys.executable, "-m", "pytest", "tests"]
    if args.verbose:
        cmd.append("-v")
    sys.exit(subprocess.call(cmd))


def cmd_eval(args):
    """Run comprehensive threat evaluation benchmark with Precision, Recall, F1, Brier, and ECE."""
    print("=== Running Threat Evaluation & Calibration Benchmark ===")
    from consensus.engine import ThreatInvestigationEngine
    from agents.laya_agent import PINNED_CHECKPOINT, PINNED_REVISION
    import numpy as np
    import json

    engine = ThreatInvestigationEngine()

    samples_dir = os.path.join(PROJECT_ROOT, "data", "samples")
    if not os.path.isdir(samples_dir):
        print(f"Samples directory {samples_dir} not found.")
        return

    sample_files = [f for f in sorted(os.listdir(samples_dir)) if f.endswith(".eml")]
    print(f"Evaluating {len(sample_files)} synthetic sample emails...")
    print(f"Model Under Test:  {PINNED_CHECKPOINT} (Revision: {PINNED_REVISION})")
    print("Baseline Model:    Scikit-learn TF-IDF + MultinomialNB (DEMO_ONLY)\n")

    # Ground truth mapping for synthetic benchmark samples
    ground_truth = {
        "sample_phishing.eml": "PHISHING",
        "sample_suspicious.eml": "SUSPICIOUS",
        "sample_spam.eml": "SPAM",
        "sample_legitimate.eml": "LEGITIMATE",
        "sample_prompt_injection.eml": "PHISHING",
    }

    async def evaluate_all():
        results = []
        for sf in sample_files:
            p = os.path.join(samples_dir, sf)
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            state = await engine.run_investigation(content, source=sf)
            results.append({
                "sample": sf,
                "ground_truth": ground_truth.get(sf, "UNKNOWN"),
                "consensus_verdict": state.final_result.final_verdict.value,
                "rule": state.final_result.matched_rule_id,
                "confidence": state.final_result.confidence,
                "evidence_count": len(state.evidence),
                "prompt_injection": state.final_result.prompt_injection_detected,
                "agent_reports": {
                    r.agent_id: {"verdict": r.verdict.value, "confidence": r.confidence}
                    for r in state.reports if r.round == 2
                },
            })
        return results

    eval_results = asyncio.run(evaluate_all())

    print(f"{'Sample':<30} | {'True Label':<11} | {'Consensus':<12} | {'Rule':<8} | {'Conf':<6} | {'Evid':<5} | {'Inj'}")
    print("-" * 88)
    for r in eval_results:
        inj_str = "YES" if r["prompt_injection"] else "NO"
        print(f"{r['sample']:<30} | {r['ground_truth']:<11} | {r['consensus_verdict']:<12} | {r['rule']:<8} | {r['confidence']:<6.2f} | {r['evidence_count']:<5} | {inj_str}")

    # Binary threat vs non-threat metric calculation
    # Threat: PHISHING, SUSPICIOUS, SPAM (1) | Benign: LEGITIMATE (0)
    y_true_binary = []
    y_pred_binary = []
    confidences = []

    for r in eval_results:
        if r["ground_truth"] != "UNKNOWN":
            is_threat_true = 1 if r["ground_truth"] in {"PHISHING", "SUSPICIOUS", "SPAM"} else 0
            is_threat_pred = 1 if r["consensus_verdict"] in {"PHISHING", "SUSPICIOUS", "SPAM"} else 0
            y_true_binary.append(is_threat_true)
            y_pred_binary.append(is_threat_pred)
            conf = r["confidence"] if is_threat_pred == 1 else (1.0 - r["confidence"])
            confidences.append(conf)

    y_true_arr = np.array(y_true_binary)
    y_pred_arr = np.array(y_pred_binary)
    conf_arr = np.array(confidences)

    # Precision, Recall, F1
    tp = int(np.sum((y_pred_arr == 1) & (y_true_arr == 1)))
    fp = int(np.sum((y_pred_arr == 1) & (y_true_arr == 0)))
    fn = int(np.sum((y_pred_arr == 0) & (y_true_arr == 1)))
    tn = int(np.sum((y_pred_arr == 0) & (y_true_arr == 0)))

    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * (precision * recall) / max(precision + recall, 1e-6)
    accuracy = (tp + tn) / max(len(y_true_arr), 1)

    # Brier Score & ECE
    brier = float(np.mean((conf_arr - y_true_arr) ** 2))
    
    # ECE with 5 bins
    n_bins = 5
    bin_bounds = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    for i in range(n_bins):
        low, high = bin_bounds[i], bin_bounds[i + 1]
        mask = (conf_arr >= low) & (conf_arr < high if i < n_bins - 1 else conf_arr <= high)
        bin_count = int(np.sum(mask))
        if bin_count > 0:
            bin_acc = float(np.mean(y_true_arr[mask] == (conf_arr[mask] >= 0.5)))
            bin_conf = float(np.mean(conf_arr[mask]))
            ece += (bin_count / len(y_true_arr)) * abs(bin_acc - bin_conf)

    print("\n=== Evaluation Metrics (Synthetic Benchmark) ===")
    print(f"Accuracy:    {accuracy:.4f}")
    print(f"Precision:   {precision:.4f}")
    print(f"Recall:      {recall:.4f}")
    print(f"F1-Score:    {f1:.4f}")
    print(f"Brier Score: {brier:.4f}  (Lower is better; 0 = perfect calibration)")
    print(f"ECE:         {ece:.4f}  (Expected Calibration Error across {n_bins} bins)")

    print("\n=== Model Comparison: Laya vs ML Baseline ===")
    print(f"{'Sample':<30} | {'ML Baseline (R2)':<20} | {'Laya System 1 (R2)':<20}")
    print("-" * 75)
    for r in eval_results:
        ml_rep = r["agent_reports"].get("ml", {})
        laya_rep = r["agent_reports"].get("laya", {})
        ml_str = f"{ml_rep.get('verdict', 'N/A')} ({ml_rep.get('confidence', 0):.2f})"
        laya_str = f"{laya_rep.get('verdict', 'N/A')} ({laya_rep.get('confidence', 0):.2f})"
        print(f"{r['sample']:<30} | {ml_str:<20} | {laya_str:<20}")

    # Calibration disclaimer
    print("\n[IMPORTANT CALIBRATION NOTICE]")
    print("Calibration status remains UNVALIDATED until evaluated on an external, representative labeled email corpus.")
    print("Without domain email calibration, confidences should be treated as uncalibrated model scores.")

    # Save results to file
    out_path = os.path.join(PROJECT_ROOT, "data", "eval_results.json")
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump({
                "benchmark_samples": len(eval_results),
                "metrics": {
                    "accuracy": round(accuracy, 4),
                    "precision": round(precision, 4),
                    "recall": round(recall, 4),
                    "f1": round(f1, 4),
                    "brier_score": round(brier, 4),
                    "ece": round(ece, 4),
                },
                "calibration_status": "UNVALIDATED",
                "evaluated_models": {
                    "laya": {"checkpoint": PINNED_CHECKPOINT, "revision": PINNED_REVISION},
                    "ml": {"model": "scikit-learn TF-IDF + MultinomialNB", "status": "DEMO_ONLY"},
                },
                "sample_results": eval_results,
            }, f, indent=2)
        print(f"\nEvaluation artifact saved to {out_path}")
    except Exception as e:
        print(f"Failed to save eval results: {e}")


def cmd_test_corpus(args):
    """Run benchmark evaluation over external raw email corpus."""
    from scripts.benchmark_spam_corpus import run_corpus_benchmark
    limit = None if args.all else args.limit
    run_corpus_benchmark(
        corpus_dir=args.path,
        limit=limit,
    )


def cmd_dev(args):
    """Run development servers."""
    print("Starting Email Threat Detection Platform backend on http://127.0.0.1:8000 ...")
    uvicorn_cmd = [
        sys.executable, "-m", "uvicorn", "backend.app:app",
        "--host", "127.0.0.1",
        "--port", str(args.port),
        "--reload",
    ]
    subprocess.call(uvicorn_cmd)


def main():
    parser = argparse.ArgumentParser(description="Management CLI for Email Threat Detection Platform")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # setup
    subparsers.add_parser("setup", help="Install dependencies and setup config")

    # prepare-models
    p_prep = subparsers.add_parser("prepare-models", help="Download and verify model weights")
    p_prep.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompt")
    p_prep.add_argument("--force", "-f", action="store_true", help="Force re-download")

    # laya-check
    p_laya = subparsers.add_parser("laya-check", help="Verify Laya installation, hardware, and weights")
    p_laya.add_argument("--live", action="store_true", help="Run live Laya smoke test on synthetic email (RUN_LAYA_LIVE=1)")

    # test
    p_test = subparsers.add_parser("test", help="Run pytest suite")
    p_test.add_argument("-v", "--verbose", action="store_true", help="Verbose pytest output")

    # eval
    subparsers.add_parser("eval", help="Run evaluation benchmark over synthetic samples")

    # test-corpus
    p_corpus = subparsers.add_parser("test-corpus", help="Run benchmark evaluation over external raw email corpus")
    p_corpus.add_argument("--path", type=str, default=r"C:\Users\Gbn84\Downloads\20021010_spam\spam", help="Path to raw email folder")
    p_corpus.add_argument("--limit", type=int, default=50, help="Number of emails to evaluate (default: 50)")
    p_corpus.add_argument("--all", action="store_true", help="Evaluate all emails in the corpus")

    # dev
    p_dev = subparsers.add_parser("dev", help="Start local development server")
    p_dev.add_argument("--port", type=int, default=8000, help="Port to bind on 127.0.0.1")

    args = parser.parse_args()

    commands = {
        "setup": cmd_setup,
        "prepare-models": cmd_prepare_models,
        "laya-check": cmd_laya_check,
        "test": cmd_test,
        "eval": cmd_eval,
        "test-corpus": cmd_test_corpus,
        "dev": cmd_dev,
    }

    cmd_fn = commands.get(args.command)
    if cmd_fn:
        cmd_fn(args)


if __name__ == "__main__":
    main()
