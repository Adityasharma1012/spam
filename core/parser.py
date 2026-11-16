"""Deterministic email parser and evidence extractor.

Extracts structured evidence items (EV-001...) from RFC 5322/2822 emails.
Treats all email content strictly as untrusted data.
Never resolves external domains, never visits URLs, and never executes attachments.
"""
import email
from email import policy
from email.message import EmailMessage
import hashlib
import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple

from core.defang import defang_domain, defang_url, extract_and_defang_urls
from core.geoip import geolocate_public_ip, is_public_routable_ip
from core.models import EvidenceCategory, EvidenceItem, PARSER_VERSION

# Safety limits
MAX_RAW_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB limit
MAX_MIME_DEPTH = 10                     # Prevent MIME recursion bombs
MAX_ATTACHMENTS = 50                    # Cap attachment count

# Prompt Injection detection signatures (treated as evidence, never instructions)
PROMPT_INJECTION_PATTERNS = [
    (re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", re.I), "Directive: 'Ignore previous instructions'"),
    (re.compile(r"system\s*prompt\s*:", re.I), "Directive: 'System prompt:'"),
    (re.compile(r"<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]", re.I), "LLM delimiter token injection"),
    (re.compile(r"(you\s+must|please)\s+(classify|mark|declare|judge)\s+(this|the)\s+email\s+as\s+(legitimate|safe|clean)", re.I), "Adversarial verdict override directive"),
    (re.compile(r"verdict\s*[:=]\s*(legitimate|safe)", re.I), "Adversarial verdict definition injection"),
    (re.compile(r"override\s+security\s+protocol", re.I), "Directive: 'Override security protocol'"),
]

# IPv4 extraction pattern
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class EmailParser:
    """Deterministic parser extracting EV-001... evidence items."""

    def __init__(self, parser_version: str = PARSER_VERSION):
        self.parser_version = parser_version

    def parse(self, raw_content: str | bytes) -> Tuple[Dict[str, Any], List[EvidenceItem]]:
        """Parse raw email content into structured metadata and evidence items."""
        if isinstance(raw_content, str):
            raw_bytes = raw_content.encode("utf-8", errors="replace")
        else:
            raw_bytes = raw_content

        if len(raw_bytes) > MAX_RAW_SIZE_BYTES:
            raise ValueError(f"Email size {len(raw_bytes)} bytes exceeds maximum {MAX_RAW_SIZE_BYTES} bytes")

        email_sha256 = hashlib.sha256(raw_bytes).hexdigest()

        try:
            msg = email.message_from_bytes(raw_bytes, policy=policy.default)
        except Exception as e:
            raise ValueError(f"Failed to parse email message: {e}")

        evidence_counter = 1

        def next_ev_id() -> str:
            nonlocal evidence_counter
            eid = f"EV-{evidence_counter:03d}"
            evidence_counter += 1
            return eid

        evidence_items: List[EvidenceItem] = []

        # 1. Header Extraction
        from_hdr = str(msg.get("From", "")).strip()
        reply_to_hdr = str(msg.get("Reply-To", "")).strip()
        return_path_hdr = str(msg.get("Return-Path", "")).strip()
        subject_hdr = str(msg.get("Subject", "")).strip()
        date_hdr = str(msg.get("Date", "")).strip()
        message_id_hdr = str(msg.get("Message-ID", "")).strip()

        # 2. Check for Address Mismatches (From vs Reply-To vs Return-Path)
        from_addr = email.utils.parseaddr(from_hdr)[1].lower()
        reply_to_addr = email.utils.parseaddr(reply_to_hdr)[1].lower()
        return_path_addr = email.utils.parseaddr(return_path_hdr)[1].lower()

        from_domain = from_addr.split("@")[-1] if "@" in from_addr else ""
        reply_domain = reply_to_addr.split("@")[-1] if "@" in reply_to_addr else ""
        return_domain = return_path_addr.split("@")[-1] if "@" in return_path_addr else ""

        if reply_to_addr and reply_to_addr != from_addr:
            evidence_items.append(EvidenceItem(
                evidence_id=next_ev_id(),
                category=EvidenceCategory.HEADER_MISMATCH,
                description=f"From address ({defang_domain(from_addr)}) differs from Reply-To address ({defang_domain(reply_to_addr)})",
                source="Headers: From / Reply-To",
                parser_version=self.parser_version,
                provenance="Extracted and compared RFC 5322 From and Reply-To headers",
                raw_data={"from": from_addr, "reply_to": reply_to_addr},
                defanged_data={"from": defang_domain(from_addr), "reply_to": defang_domain(reply_to_addr)},
                severity="HIGH" if from_domain != reply_domain else "MEDIUM",
            ))

        if return_path_addr and return_path_addr != from_addr:
            if return_domain and from_domain and return_domain != from_domain:
                evidence_items.append(EvidenceItem(
                    evidence_id=next_ev_id(),
                    category=EvidenceCategory.HEADER_MISMATCH,
                    description=f"From domain ({defang_domain(from_domain)}) differs from Return-Path domain ({defang_domain(return_domain)})",
                    source="Headers: From / Return-Path",
                    parser_version=self.parser_version,
                    provenance="Extracted and compared RFC 5322 From and Return-Path domains",
                    raw_data={"from_domain": from_domain, "return_path_domain": return_domain},
                    defanged_data={"from_domain": defang_domain(from_domain), "return_path_domain": defang_domain(return_domain)},
                    severity="MEDIUM",
                ))

        # 3. Authentication Results (SPF, DKIM, DMARC)
        auth_results_hdrs = msg.get_all("Authentication-Results", [])
        received_spf_hdrs = msg.get_all("Received-SPF", [])

        auth_evidence_data = {"spf": None, "dkim": None, "dmarc": None, "raw_auth_headers": []}

        for auth_h in auth_results_hdrs:
            h_str = str(auth_h)
            auth_evidence_data["raw_auth_headers"].append(h_str)
            if "spf=" in h_str.lower():
                spf_match = re.search(r"spf=([a-zA-Z]+)", h_str, re.I)
                if spf_match:
                    auth_evidence_data["spf"] = spf_match.group(1).lower()
            if "dkim=" in h_str.lower():
                dkim_match = re.search(r"dkim=([a-zA-Z]+)", h_str, re.I)
                if dkim_match:
                    auth_evidence_data["dkim"] = dkim_match.group(1).lower()
            if "dmarc=" in h_str.lower():
                dmarc_match = re.search(r"dmarc=([a-zA-Z]+)", h_str, re.I)
                if dmarc_match:
                    auth_evidence_data["dmarc"] = dmarc_match.group(1).lower()

        for spf_h in received_spf_hdrs:
            h_str = str(spf_h)
            auth_evidence_data["raw_auth_headers"].append(h_str)
            if not auth_evidence_data["spf"]:
                parts = h_str.split()
                if parts:
                    auth_evidence_data["spf"] = parts[0].lower()

        # If any authentication result is present, record evidence
        if auth_evidence_data["spf"] or auth_evidence_data["dkim"] or auth_evidence_data["dmarc"]:
            failures = []
            if auth_evidence_data["spf"] in {"fail", "softfail"}:
                failures.append(f"SPF {auth_evidence_data['spf'].upper()}")
            if auth_evidence_data["dkim"] in {"fail"}:
                failures.append(f"DKIM {auth_evidence_data['dkim'].upper()}")
            if auth_evidence_data["dmarc"] in {"fail"}:
                failures.append(f"DMARC {auth_evidence_data['dmarc'].upper()}")

            severity = "HIGH" if failures else "INFO"
            desc = f"Email authentication status: SPF={auth_evidence_data['spf']}, DKIM={auth_evidence_data['dkim']}, DMARC={auth_evidence_data['dmarc']}"
            if failures:
                desc += f" (FAILURES DETECTED: {', '.join(failures)})"

            evidence_items.append(EvidenceItem(
                evidence_id=next_ev_id(),
                category=EvidenceCategory.AUTH_RESULTS,
                description=desc,
                source="Authentication-Results / Received-SPF",
                parser_version=self.parser_version,
                provenance="Parsed RFC 8601 Authentication-Results and RFC 7208 Received-SPF headers",
                raw_data=auth_evidence_data,
                defanged_data=auth_evidence_data,
                severity=severity,
            ))
        else:
            # Missing authentication headers altogether is notable
            evidence_items.append(EvidenceItem(
                evidence_id=next_ev_id(),
                category=EvidenceCategory.AUTH_RESULTS,
                description="No SPF, DKIM, or DMARC authentication headers found in message",
                source="Headers: Authentication-Results",
                parser_version=self.parser_version,
                provenance="Examined headers for RFC 8601 / RFC 7208 entries",
                raw_data={"auth_present": False},
                defanged_data={"auth_present": False},
                severity="MEDIUM",
            ))

        # 4. Received Chain and Candidate IPs
        received_hdrs = msg.get_all("Received", [])
        received_ips = []
        for r_hdr in received_hdrs:
            ips = IPV4_PATTERN.findall(str(r_hdr))
            for ip in ips:
                if is_public_routable_ip(ip) and ip not in received_ips:
                    received_ips.append(ip)

        evidence_items.append(EvidenceItem(
            evidence_id=next_ev_id(),
            category=EvidenceCategory.RECEIVED_CHAIN,
            description=f"Received chain contains {len(received_hdrs)} hops. Note: Received headers may be forged by upstream senders.",
            source="Headers: Received",
            parser_version=self.parser_version,
            provenance="Extracted sequential RFC 5322 Received headers",
            raw_data={"hop_count": len(received_hdrs), "candidate_public_ips": received_ips},
            defanged_data={"hop_count": len(received_hdrs), "candidate_public_ips": [ip.replace(".", "[.]") for ip in received_ips]},
            severity="INFO",
        ))

        # Candidate IP geolocation notice (approximate network-level location)
        for cand_ip in received_ips[:3]:  # Top hops
            geo = geolocate_public_ip(cand_ip)
            if geo:
                geo_desc = (
                    f"Routable public IP {cand_ip.replace('.', '[.]')} identified in delivery chain. "
                    f"Network location: {geo['country']} ({geo['city']}), ASN: {geo['asn']} ({geo['isp']}). "
                    f"Label: {geo['disclaimer']}"
                )
                evidence_items.append(EvidenceItem(
                    evidence_id=next_ev_id(),
                    category=EvidenceCategory.IP_REPUTATION,
                    description=geo_desc,
                    source="Headers: Received (Network Geolocation)",
                    parser_version=self.parser_version,
                    provenance="Resolved public IPv4 subnet against local network geolocation table",
                    raw_data=geo,
                    defanged_data={**geo, "ip": cand_ip.replace(".", "[.]")},
                    severity="INFO",
                ))

        # 5. Body Extraction & MIME Hierarchy Traversal
        body_text = ""
        body_html = ""
        attachments_meta = []
        depth_level = 0

        def walk_parts(part, depth=0):
            nonlocal body_text, body_html, attachments_meta, depth_level
            if depth > MAX_MIME_DEPTH:
                raise ValueError(f"MIME nesting depth exceeded limit of {MAX_MIME_DEPTH}")
            if depth > depth_level:
                depth_level = depth

            content_type = part.get_content_type()
            content_disposition = str(part.get_content_disposition() or "").lower()

            if content_disposition == "attachment" or part.get_filename() or (not part.is_multipart() and content_type not in {"text/plain", "text/html"}):
                if len(attachments_meta) < MAX_ATTACHMENTS:
                    filename = part.get_filename() or f"attachment_{len(attachments_meta)+1}.bin"
                    payload = part.get_payload(decode=True) or b""
                    att_sha256 = hashlib.sha256(payload).hexdigest()
                    attachments_meta.append({
                        "filename": filename,
                        "content_type": content_type,
                        "size_bytes": len(payload),
                        "sha256": att_sha256,
                    })
                return

            if content_type == "text/plain" and not body_text:
                payload = part.get_payload(decode=True)
                if payload:
                    body_text = payload.decode(errors="replace")
            elif content_type == "text/html" and not body_html:
                payload = part.get_payload(decode=True)
                if payload:
                    body_html = payload.decode(errors="replace")

            if part.is_multipart():
                for subpart in part.iter_parts():
                    walk_parts(subpart, depth + 1)

        walk_parts(msg)

        # 6. Attachment Evidence
        for att in attachments_meta:
            is_suspicious_ext = any(att["filename"].lower().endswith(ext) for ext in [
                ".exe", ".scr", ".vbs", ".bat", ".cmd", ".iso", ".zip", ".tar.gz", ".xlsm", ".docm", ".js", ".ps1"
            ])
            severity = "HIGH" if is_suspicious_ext else "INFO"
            desc = f"Attachment found: {att['filename']} ({att['content_type']}, {att['size_bytes']} bytes, SHA-256: {att['sha256'][:16]}...)"
            if is_suspicious_ext:
                desc += " - Suspicious or executable file extension detected!"

            evidence_items.append(EvidenceItem(
                evidence_id=next_ev_id(),
                category=EvidenceCategory.ATTACHMENT_ANALYSIS,
                description=desc,
                source="MIME Attachment",
                parser_version=self.parser_version,
                provenance="Computed SHA-256 hash and parsed MIME parameters (never executed)",
                raw_data=att,
                defanged_data={**att, "filename": att["filename"].replace(".", "[.]")},
                severity=severity,
            ))

        # 7. URL Extraction & Defanging
        combined_text = f"{body_text}\n{body_html}"
        extracted_urls = extract_and_defang_urls(combined_text)

        for u in extracted_urls:
            raw_url = u["raw_url"]
            defanged = u["defanged_url"]

            # Heuristic check for phishing indicators in URL
            is_ip_url = bool(re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", raw_url))
            is_brand_spoof = any(brand in raw_url.lower() for brand in ["paypal", "microsoft", "google", "apple", "wellsfargo", "chase", "bankofamerica"]) and not any(
                legit in raw_url.lower() for legit in ["paypal.com", "microsoft.com", "google.com", "apple.com", "wellsfargo.com", "chase.com"]
            )

            severity = "CRITICAL" if (is_ip_url or is_brand_spoof) else "LOW"
            desc = f"Observed URL in body: {defanged}"
            if is_ip_url:
                desc += " (Uses raw IP address instead of domain hostname)"
            if is_brand_spoof:
                desc += " (Potential target brand name spoofed in unregistered domain/path)"

            evidence_items.append(EvidenceItem(
                evidence_id=next_ev_id(),
                category=EvidenceCategory.URL_ANALYSIS,
                description=desc,
                source="Email Body",
                parser_version=self.parser_version,
                provenance="Extracted link with regex and defanged for display (never dereferenced)",
                raw_data={"url": raw_url, "ip_based": is_ip_url, "brand_spoof_heuristic": is_brand_spoof},
                defanged_data={"url": defanged, "ip_based": is_ip_url, "brand_spoof_heuristic": is_brand_spoof},
                severity=severity,
            ))

        # 8. Prompt Injection Scanning (Headers + Body + Attachment Filenames)
        all_headers_str = "\n".join([f"{k}: {v}" for k, v in msg.items()])
        att_names_str = "\n".join([att["filename"] for att in attachments_meta])
        scanned_content = f"{all_headers_str}\n{body_text}\n{body_html}\n{att_names_str}"
        injection_findings = []
        for pat, rule_desc in PROMPT_INJECTION_PATTERNS:
            match = pat.search(scanned_content)
            if match:
                injection_findings.append({
                    "rule": rule_desc,
                    "matched_substring": match.group(0)[:60]
                })

        if injection_findings:
            evidence_items.append(EvidenceItem(
                evidence_id=next_ev_id(),
                category=EvidenceCategory.PROMPT_INJECTION,
                description=f"Prompt injection attempt detected: {len(injection_findings)} pattern(s) matched. Attempt must NOT alter verdicts.",
                source="Content Scanner",
                parser_version=self.parser_version,
                provenance="Matched known LLM prompt-override and delimiter injection heuristics",
                raw_data={"injections": injection_findings},
                defanged_data={"injections": injection_findings},
                severity="CRITICAL",
            ))

        parsed_metadata = {
            "email_sha256": email_sha256,
            "subject": subject_hdr,
            "from": from_hdr,
            "reply_to": reply_to_hdr,
            "return_path": return_path_hdr,
            "date": date_hdr,
            "message_id": message_id_hdr,
            "body_plain": body_text,
            "body_html": body_html,
            "has_html": bool(body_html),
            "attachment_count": len(attachments_meta),
            "attachment_bytes_total": sum(att["size_bytes"] for att in attachments_meta),
            "url_count": len(extracted_urls),
            "mime_depth": depth_level,
        }

        return parsed_metadata, evidence_items
