"""Compute exact per-agent and consensus metrics across the benchmark dataset."""
import json
import numpy as np

with open('data/eval_results.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

samples = data['sample_results']

print(f"Total evaluated samples: {len(samples)}\n")

# Evaluation functions
def evaluate_agent(name, extract_fn):
    exact_correct = 0
    binary_tp = 0
    binary_fp = 0
    binary_fn = 0
    binary_tn = 0
    
    print(f"--- Agent: {name} ---")
    for s in samples:
        gt = s['ground_truth']
        pred, conf = extract_fn(s)
        
        # 4-class exact match
        is_exact = (pred == gt)
        if is_exact:
            exact_correct += 1
            
        # Binary threat match: Threat (PHISHING, SUSPICIOUS, SPAM) vs Benign (LEGITIMATE)
        gt_threat = 1 if gt in {'PHISHING', 'SUSPICIOUS', 'SPAM'} else 0
        pred_threat = 1 if pred in {'PHISHING', 'SUSPICIOUS', 'SPAM'} else 0
        
        if pred == 'ABSTAIN':
            pred_threat = -1 # Abstain
            
        if pred_threat == 1 and gt_threat == 1:
            binary_tp += 1
        elif pred_threat == 1 and gt_threat == 0:
            binary_fp += 1
        elif pred_threat == 0 and gt_threat == 1:
            binary_fn += 1
        elif pred_threat == 0 and gt_threat == 0:
            binary_tn += 1
            
        print(f"  {s['sample']:<30} | True: {gt:<11} | Pred: {pred:<12} | Conf: {conf:.2f}")

    exact_acc = exact_correct / len(samples)
    binary_acc = (binary_tp + binary_tn) / len(samples)
    precision = binary_tp / max(binary_tp + binary_fp, 1)
    recall = binary_tp / max(binary_tp + binary_fn, 1)
    f1 = 2 * (precision * recall) / max(precision + recall, 1e-6)
    
    print(f"  -> Exact 4-Class Accuracy:     {exact_acc * 100:.1f}% ({exact_correct}/{len(samples)})")
    print(f"  -> Binary Threat Detection Acc: {binary_acc * 100:.1f}% ({binary_tp + binary_tn}/{len(samples)})")
    print(f"  -> Precision:                  {precision:.4f}")
    print(f"  -> Recall:                     {recall:.4f}")
    print(f"  -> F1-Score:                   {f1:.4f}\n")
    return {
        "exact_acc": exact_acc,
        "binary_acc": binary_acc,
        "precision": precision,
        "recall": recall,
        "f1": f1
    }

# 1. Agent 1: ML Baseline (TF-IDF + Naive Bayes)
ml_metrics = evaluate_agent("Agent 1: ML Baseline (TF-IDF + Naive Bayes)", lambda s: (s['agent_reports']['ml']['verdict'], s['agent_reports']['ml']['confidence']))

# 2. Agent 2: Gemini Adapter (Privacy Gated - Disabled by default)
gemini_metrics = evaluate_agent("Agent 2: Gemini Adapter (Privacy Gated - OFF)", lambda s: (s['agent_reports']['gemini']['verdict'], s['agent_reports']['gemini']['confidence']))

# 3. Agent 3: Laya System 1 (ModernBERT-large, Pinned Checkpoint)
laya_metrics = evaluate_agent("Agent 3: Laya System 1 Decision Model", lambda s: (s['agent_reports']['laya']['verdict'], s['agent_reports']['laya']['confidence']))

# 4. Consensus Engine
consensus_metrics = evaluate_agent("Consensus Engine (Multi-Agent System)", lambda s: (s['consensus_verdict'], s['confidence']))
