#!/bin/bash
# ══════════════════════════════════════════════════════
#  MOD 11: Report Generator (HTML + MD + TXT)
# ══════════════════════════════════════════════════════

mod_report() {
  log_section "MOD 11: Report Generation"
  local RPT="$OUTPUT_DIR/reports"

  END_TIME=$(date +%s)
  DURATION=$(( (END_TIME - START_TIME) / 60 ))

  TOTAL_SUBS=$(wc -l < "$OUTPUT_DIR/subdomains/all_subdomains.txt" 2>/dev/null || echo 0)
  LIVE_SUBS=$(wc -l < "$OUTPUT_DIR/subdomains/live.txt" 2>/dev/null || echo 0)
  TOTAL_URLS=$(wc -l < "$OUTPUT_DIR/urls/all_urls.txt" 2>/dev/null || echo 0)
  TOTAL_PARAMS=$(wc -l < "$OUTPUT_DIR/urls/unique_params.txt" 2>/dev/null || echo 0)
  TOTAL_JS=$(wc -l < "$OUTPUT_DIR/urls/js_files.txt" 2>/dev/null || echo 0)
  CRIT=$(grep -ri "\[critical\]" "$OUTPUT_DIR/vulns/" 2>/dev/null | wc -l || echo 0)
  HIGH=$(grep -ri "\[high\]" "$OUTPUT_DIR/vulns/" 2>/dev/null | wc -l || echo 0)
  MED=$(grep -ri "\[medium\]" "$OUTPUT_DIR/vulns/" 2>/dev/null | wc -l || echo 0)
  LOW=$(grep -ri "\[low\]" "$OUTPUT_DIR/vulns/" 2>/dev/null | wc -l || echo 0)
  TOTAL_VULNS=$((CRIT + HIGH + MED + LOW))
  SCORE=$(( (CRIT*10) + (HIGH*5) + (MED*2) + LOW ))
  V4_FINDINGS=$(wc -l < "$OUTPUT_DIR/vulns/v4/findings.txt" 2>/dev/null || echo 0)
  V4_JS=$(wc -l < "$OUTPUT_DIR/vulns/v4/js/fingerprints.tsv" 2>/dev/null || echo 0)
  V4_CSP=$(wc -l < "$OUTPUT_DIR/vulns/v4/csp/csp_risk.tsv" 2>/dev/null || echo 0)
  V4_GRAPHQL=$(wc -l < "$OUTPUT_DIR/vulns/v4/graphql/schema_graph.tsv" 2>/dev/null || echo 0)
  V4_SSRF=$(wc -l < "$OUTPUT_DIR/vulns/v4/ssrf/candidates.tsv" 2>/dev/null || echo 0)
  V4_API=$(cat "$OUTPUT_DIR/vulns/v4/api_auth"/*.txt 2>/dev/null | wc -l || echo 0)
  [[ $SCORE -ge 50 ]] && RISK="CRITICAL" || \
  [[ $SCORE -ge 20 ]] && RISK="HIGH" || \
  [[ $SCORE -ge 5  ]] && RISK="MEDIUM" || \
  [[ $SCORE -ge 1  ]] && RISK="LOW" || RISK="INFO"

  # ── HTML ─────────────────────────────────────────────
  cat > "$RPT/report.html" << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BugHunter Pro v4.0 — $DOMAIN</title>
<style>
:root{--bg:#07080f;--s1:#0d0f1c;--s2:#131626;--s3:#191c30;--brd:#1f2340;
--acc:#e94560;--acc2:#4fc3f7;--txt:#cdd6f4;--mut:#6c7086;
--crit:#ff4560;--high:#ff8c42;--med:#ffd166;--low:#06d6a0;--inf:#4fc3f7}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--txt);font-family:'Courier New',monospace;font-size:13px}
.hdr{background:linear-gradient(135deg,#07080f 0%,#12052a 50%,#071228 100%);
  padding:50px 30px;text-align:center;border-bottom:1px solid var(--brd);
  position:relative;overflow:hidden}
.hdr::before{content:'';position:absolute;inset:0;
  background:radial-gradient(ellipse at 50% 0%,rgba(233,69,96,.2) 0%,transparent 70%)}
.hdr h1{font-size:2.8em;color:var(--acc);letter-spacing:5px;
  text-shadow:0 0 40px rgba(233,69,96,.6);position:relative;z-index:1}
.hdr .domain{font-size:1.6em;color:var(--acc2);margin:12px 0;
  text-shadow:0 0 20px rgba(79,195,247,.4);position:relative;z-index:1}
.hdr .meta{color:var(--mut);font-size:.82em;position:relative;z-index:1}
.wrap{max-width:1500px;margin:0 auto;padding:25px}
.risk{text-align:center;padding:18px;margin:20px 0;border-radius:6px;
  font-size:1.4em;font-weight:bold;letter-spacing:3px}
.rCRITICAL{background:rgba(255,69,96,.15);border:2px solid var(--crit);color:var(--crit)}
.rHIGH{background:rgba(255,140,66,.15);border:2px solid var(--high);color:var(--high)}
.rMEDIUM{background:rgba(255,209,102,.15);border:2px solid var(--med);color:var(--med)}
.rLOW{background:rgba(6,214,160,.15);border:2px solid var(--low);color:var(--low)}
.rINFO{background:rgba(79,195,247,.1);border:2px solid var(--inf);color:var(--inf)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:20px 0}
.stat{background:var(--s1);border:1px solid var(--brd);border-radius:8px;
  padding:18px;text-align:center;transition:.2s}
.stat:hover{border-color:var(--acc);transform:translateY(-2px)}
.sn{font-size:2.4em;font-weight:bold;line-height:1}
.sl{color:var(--mut);font-size:.75em;margin-top:5px;text-transform:uppercase;letter-spacing:1px}
.c{color:var(--crit)}.h{color:var(--high)}.m{color:var(--med)}.l{color:var(--low)}.i{color:var(--inf)}.g{color:#a6e3a1}
.card{background:var(--s1);border:1px solid var(--brd);border-radius:8px;margin:12px 0;overflow:hidden}
.ch{background:var(--s2);padding:12px 18px;display:flex;justify-content:space-between;
  align-items:center;cursor:pointer;border-bottom:1px solid var(--brd)}
.ch:hover{background:var(--s3)}.card.open .ch{border-color:var(--acc)}
.ct{color:var(--acc2);font-weight:bold}.cb{background:var(--s3);border-radius:10px;
  padding:2px 10px;font-size:.72em}
.cb.z{background:#1a1a2a;color:var(--mut)}
.cd{padding:18px;display:none}.card.open .cd{display:block}
pre{background:#050508;border:1px solid #141428;border-radius:5px;padding:12px;
  overflow:auto;color:#90d090;font-size:.8em;max-height:450px;
  white-space:pre-wrap;word-break:break-all;line-height:1.5}
table{width:100%;border-collapse:collapse;font-size:.84em}
th{background:var(--s3);color:var(--acc2);padding:9px 14px;text-align:left;
  font-size:.76em;letter-spacing:1px;text-transform:uppercase}
td{padding:9px 14px;border-bottom:1px solid var(--brd)}
tr:hover td{background:var(--s2)}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.7em;font-weight:bold}
.bc{background:var(--crit);color:#fff}.bh{background:var(--high);color:#fff}
.bm{background:var(--med);color:#000}.bl{background:var(--low);color:#000}
.bi{background:#1a2a3a;color:var(--inf)}
.tabs{display:flex;gap:5px;margin:12px 0;flex-wrap:wrap}
.tab{background:var(--s2);border:1px solid var(--brd);border-radius:4px;
  padding:5px 12px;cursor:pointer;font-size:.78em;color:var(--mut)}
.tab.a,.tab:hover{background:var(--acc);color:#fff;border-color:var(--acc)}
.tc{display:none}.tc.a{display:block}
.ftr{text-align:center;padding:25px;color:var(--mut);
  border-top:1px solid var(--brd);margin-top:30px}
a{color:var(--acc2);text-decoration:none}a:hover{text-decoration:underline}
.stitle{color:var(--acc);margin:15px 0 8px;padding-bottom:6px;
  border-bottom:1px solid var(--brd)}
</style>
</head>
<body>
<div class="hdr">
  <h1>🔍 BUGHUNTER PRO</h1>
  <div class="domain">$DOMAIN</div>
  <div class="meta">
    📅 $(date '+%Y-%m-%d %H:%M') &nbsp;|&nbsp; ⏱ ${DURATION}m &nbsp;|&nbsp;
    🔧 v4.0 Ultimate &nbsp;|&nbsp; 🎯 50+ Tools
  </div>
</div>
<div class="wrap">

<div class="risk r$RISK">⚠ RISK: $RISK &nbsp;|&nbsp; SCORE: $SCORE &nbsp;|&nbsp; FINDINGS: $TOTAL_VULNS</div>

<div class="grid">
  <div class="stat"><div class="sn i">$TOTAL_SUBS</div><div class="sl">Subdomains</div></div>
  <div class="stat"><div class="sn g">$LIVE_SUBS</div><div class="sl">Live Hosts</div></div>
  <div class="stat"><div class="sn i">$TOTAL_URLS</div><div class="sl">URLs</div></div>
  <div class="stat"><div class="sn i">$TOTAL_PARAMS</div><div class="sl">Params</div></div>
  <div class="stat"><div class="sn i">$TOTAL_JS</div><div class="sl">JS Files</div></div>
  <div class="stat"><div class="sn c">$CRIT</div><div class="sl">Critical</div></div>
  <div class="stat"><div class="sn h">$HIGH</div><div class="sl">High</div></div>
  <div class="stat"><div class="sn m">$MED</div><div class="sl">Medium</div></div>
  <div class="stat"><div class="sn l">$LOW</div><div class="sl">Low</div></div>
  <div class="stat"><div class="sn i">$V4_FINDINGS</div><div class="sl">V4 Findings</div></div>
  <div class="stat"><div class="sn i">$V4_JS</div><div class="sl">V4 JS</div></div>
  <div class="stat"><div class="sn i">$V4_CSP</div><div class="sl">V4 CSP</div></div>
  <div class="stat"><div class="sn i">$V4_GRAPHQL</div><div class="sl">V4 GraphQL</div></div>
  <div class="stat"><div class="sn i">$V4_SSRF</div><div class="sl">V4 SSRF</div></div>
  <div class="stat"><div class="sn i">$V4_API</div><div class="sl">V4 API</div></div>
</div>

<div class="card open">
<div class="ch" onclick="tog(this)"><span class="ct">📋 All Findings</span>
<span class="cb">$(wc -l < "$OUTPUT_DIR/findings.txt" 2>/dev/null || echo 0) total</span></div>
<div class="cd"><pre>$(cat "$OUTPUT_DIR/findings.txt" 2>/dev/null | head -100 || echo "No findings recorded")</pre></div>
</div>

<div class="card open">
<div class="ch" onclick="tog(this)"><span class="ct">🔴 CVE Critical+High</span>
<span class="cb $([ $(wc -l < "$OUTPUT_DIR/vulns/nuclei/cve_critical_high.txt" 2>/dev/null || echo 0) -gt 0 ] && echo "" || echo "z")">$(wc -l < "$OUTPUT_DIR/vulns/nuclei/cve_critical_high.txt" 2>/dev/null || echo 0)</span></div>
<div class="cd"><pre>$(cat "$OUTPUT_DIR/vulns/nuclei/cve_critical_high.txt" 2>/dev/null | head -60 || echo "No critical CVEs found")</pre></div>
</div>

<div class="card">
<div class="ch" onclick="tog(this)"><span class="ct">🌐 Live Subdomains ($LIVE_SUBS / $TOTAL_SUBS)</span>
<span class="cb">$TOTAL_SUBS found</span></div>
<div class="cd">
  <p class="stitle">Technologies Detected</p>
  <pre>$(head -40 "$OUTPUT_DIR/subdomains/technologies.txt" 2>/dev/null || echo "None")</pre>
  <p class="stitle">Live URLs</p>
  <pre>$(head -80 "$OUTPUT_DIR/subdomains/live.txt" 2>/dev/null || echo "None")</pre>
</div>
</div>

<div class="card">
<div class="ch" onclick="tog(this)"><span class="ct">⚛️ Next.js / React Findings</span>
<span class="cb">$(cat "$OUTPUT_DIR/urls/nextjs_"*.txt 2>/dev/null | wc -l || echo 0)</span></div>
<div class="cd">
  <p class="stitle">API Routes</p>
  <pre>$(cat "$OUTPUT_DIR/urls/nextjs_routes.txt" 2>/dev/null | sort -u | head -40 || echo "None")</pre>
  <p class="stitle">Source Maps Exposed</p>
  <pre>$(cat "$OUTPUT_DIR/vulns/js/sourcemaps.txt" 2>/dev/null | head -20 || echo "None")</pre>
  <p class="stitle">DOM XSS Sinks</p>
  <pre>$(cat "$OUTPUT_DIR/vulns/js/dom_xss_sinks.txt" 2>/dev/null | head -20 || echo "None")</pre>
</div>
</div>

<div class="card">
<div class="ch" onclick="tog(this)"><span class="ct">🔬 All Nuclei Results</span>
<span class="cb">$(cat "$OUTPUT_DIR/vulns/nuclei/"*.txt 2>/dev/null | wc -l || echo 0)</span></div>
<div class="cd">
<div class="tabs">
  <div class="tab a" onclick="st(this,'nc')">CVEs</div>
  <div class="tab" onclick="st(this,'nm')">Misconfig</div>
  <div class="tab" onclick="st(this,'ne')">Exposures</div>
  <div class="tab" onclick="st(this,'np')">Panels</div>
  <div class="tab" onclick="st(this,'ncl')">Cloud</div>
  <div class="tab" onclick="st(this,'ncu')">Custom</div>
  <div class="tab" onclick="st(this,'nf')">Fuzzing</div>
</div>
<div id="tnc" class="tc a"><pre>$(cat "$OUTPUT_DIR/vulns/nuclei/cve_"*.txt 2>/dev/null | head -60 || echo "None")</pre></div>
<div id="tnm" class="tc"><pre>$(cat "$OUTPUT_DIR/vulns/nuclei/misconfig.txt" 2>/dev/null | head -60 || echo "None")</pre></div>
<div id="tne" class="tc"><pre>$(cat "$OUTPUT_DIR/vulns/nuclei/exposures.txt" 2>/dev/null | head -60 || echo "None")</pre></div>
<div id="tnp" class="tc"><pre>$(cat "$OUTPUT_DIR/vulns/nuclei/panels.txt" "$OUTPUT_DIR/vulns/nuclei/default_creds.txt" 2>/dev/null | head -60 || echo "None")</pre></div>
<div id="tncl" class="tc"><pre>$(cat "$OUTPUT_DIR/vulns/nuclei/cloud.txt" 2>/dev/null | head -60 || echo "None")</pre></div>
<div id="tncu" class="tc"><pre>$(cat "$OUTPUT_DIR/vulns/nuclei/custom.txt" 2>/dev/null | head -60 || echo "None")</pre></div>
<div id="tnf" class="tc"><pre>$(cat "$OUTPUT_DIR/vulns/nuclei/fuzzing.txt" 2>/dev/null | head -60 || echo "None")</pre></div>
</div>
</div>

<div class="card">
<div class="ch" onclick="tog(this)"><span class="ct">⚡ XSS</span>
<span class="cb">$(cat "$OUTPUT_DIR/vulns/xss/"*.txt 2>/dev/null | wc -l || echo 0)</span></div>
<div class="cd"><pre>$(cat "$OUTPUT_DIR/vulns/xss/"*.txt 2>/dev/null | head -40 || echo "None found")</pre></div>
</div>

<div class="card">
<div class="ch" onclick="tog(this)"><span class="ct">🔮 GraphQL</span>
<span class="cb">$(cat "$OUTPUT_DIR/vulns/graphql/"*.txt 2>/dev/null | wc -l || echo 0)</span></div>
<div class="cd"><pre>$(cat "$OUTPUT_DIR/vulns/graphql/"*.txt 2>/dev/null | head -40 || echo "None found")</pre></div>
</div>

<div class="card">
<div class="ch" onclick="tog(this)"><span class="ct">🎯 Subdomain Takeover</span>
<span class="cb">$(wc -l < "$OUTPUT_DIR/takeover/all.txt" 2>/dev/null || echo 0)</span></div>
<div class="cd"><pre>$(cat "$OUTPUT_DIR/takeover/all.txt" 2>/dev/null | head -30 || echo "None found")</pre></div>
</div>

<div class="card">
<div class="ch" onclick="tog(this)"><span class="ct">🔑 Secrets & API Keys</span>
<span class="cb">$(cat "$OUTPUT_DIR/vulns/secrets/"*.txt 2>/dev/null | wc -l || echo 0)</span></div>
<div class="cd">
  <p class="stitle">Secrets in JS/URLs</p>
  <pre>$(cat "$OUTPUT_DIR/vulns/secrets/"*.txt 2>/dev/null | grep -v "^$" | head -30 || echo "None found")</pre>
  <p class="stitle">Sensitive Files</p>
  <pre>$(cat "$OUTPUT_DIR/vulns/secrets/sensitive_files.txt" 2>/dev/null | head -20 || echo "None found")</pre>
  <p class="stitle">Git Exposed</p>
  <pre>$(cat "$OUTPUT_DIR/vulns/secrets/git_exposed.txt" 2>/dev/null | head -10 || echo "None found")</pre>
</div>
</div>

<div class="card">
<div class="ch" onclick="tog(this)"><span class="ct">🔓 CORS Misconfigurations</span>
<span class="cb">$(cat "$OUTPUT_DIR/vulns/cors/"*.txt 2>/dev/null | wc -l || echo 0)</span></div>
<div class="cd"><pre>$(cat "$OUTPUT_DIR/vulns/cors/"*.txt 2>/dev/null | head -30 || echo "None found")</pre></div>
</div>

<div class="card">
<div class="ch" onclick="tog(this)"><span class="ct">🛡️ API Testing</span>
<span class="cb">$(cat "$OUTPUT_DIR/vulns/api/"*.txt 2>/dev/null | wc -l || echo 0)</span></div>
<div class="cd">
  <p class="stitle">API Endpoints Found</p>
  <pre>$(cat "$OUTPUT_DIR/vulns/api/api_found.txt" 2>/dev/null | head -30 || echo "None")</pre>
  <p class="stitle">403 Bypass</p>
  <pre>$(cat "$OUTPUT_DIR/vulns/api/403_bypass.txt" 2>/dev/null | head -15 || echo "None")</pre>
  <p class="stitle">HTTP Methods</p>
  <pre>$(cat "$OUTPUT_DIR/vulns/api/methods_allowed.txt" 2>/dev/null | head -20 || echo "None")</pre>
</div>
</div>

<div class="card">
<div class="ch" onclick="tog(this)"><span class="ct">💉 SQLi / NoSQLi / XXE</span>
<span class="cb">$(cat "$OUTPUT_DIR/vulns/sqli/"*.txt "$OUTPUT_DIR/vulns/xxe/"*.txt 2>/dev/null | wc -l || echo 0)</span></div>
<div class="cd">
  <p class="stitle">SQL Injection</p>
  <pre>$(cat "$OUTPUT_DIR/vulns/sqli/"*.txt 2>/dev/null | head -20 || echo "None")</pre>
  <p class="stitle">XXE</p>
  <pre>$(cat "$OUTPUT_DIR/vulns/xxe/"*.txt 2>/dev/null | head -10 || echo "None")</pre>
</div>
</div>

<div class="card">
<div class="ch" onclick="tog(this)"><span class="ct">🚂 HTTP Request Smuggling</span>
<span class="cb">$(cat "$OUTPUT_DIR/vulns/smuggling/"*.txt 2>/dev/null | wc -l || echo 0)</span></div>
<div class="cd"><pre>$(cat "$OUTPUT_DIR/vulns/smuggling/"*.txt 2>/dev/null | head -20 || echo "None found")</pre></div>
</div>

<div class="card">
<div class="ch" onclick="tog(this)"><span class="ct">🛡️ WAF Detection</span>
<span class="cb">$(wc -l < "$OUTPUT_DIR/vulns/waf/fingerprint.txt" 2>/dev/null || echo 0)</span></div>
<div class="cd">
  <p class="stitle">WAF Fingerprint</p>
  <pre>$(grep -v "None detected" "$OUTPUT_DIR/vulns/waf/fingerprint.txt" 2>/dev/null | head -30 || echo "No WAF detected")</pre>
  <p class="stitle">CDN Info</p>
  <pre>$(cat "$OUTPUT_DIR/vulns/waf/cdn.txt" 2>/dev/null | head -15 || echo "None")</pre>
</div>
</div>

<div class="card">
<div class="ch" onclick="tog(this)"><span class="ct">☁️ Cloud Storage (S3/GCS/Azure/Firebase)</span>
<span class="cb">$(cat "$OUTPUT_DIR/vulns/cloud"/{s3,gcs,azure}/found.txt "$OUTPUT_DIR/vulns/cloud/firebase.txt" 2>/dev/null | grep -cE "CRITICAL|HIGH" || echo 0)</span></div>
<div class="cd">
  <p class="stitle">AWS S3</p>
  <pre>$(cat "$OUTPUT_DIR/vulns/cloud/s3/found.txt" 2>/dev/null | head -20 || echo "None found")</pre>
  <p class="stitle">GCS Buckets</p>
  <pre>$(cat "$OUTPUT_DIR/vulns/cloud/gcs/found.txt" 2>/dev/null | head -10 || echo "None found")</pre>
  <p class="stitle">Azure Blob</p>
  <pre>$(cat "$OUTPUT_DIR/vulns/cloud/azure/found.txt" 2>/dev/null | head -10 || echo "None found")</pre>
  <p class="stitle">Firebase</p>
  <pre>$(cat "$OUTPUT_DIR/vulns/cloud/firebase.txt" 2>/dev/null | head -10 || echo "None found")</pre>
</div>
</div>

<div class="card">
<div class="ch" onclick="tog(this)"><span class="ct">📧 Email Security (SPF/DKIM/DMARC)</span>
<span class="cb">$(cat "$OUTPUT_DIR/vulns/email"/*.txt 2>/dev/null | grep -cE "CRITICAL|HIGH" || echo 0)</span></div>
<div class="cd">
  <pre>$(cat "$OUTPUT_DIR/vulns/email/summary.txt" 2>/dev/null)

$(cat "$OUTPUT_DIR/vulns/email/spf.txt" "$OUTPUT_DIR/vulns/email/dmarc.txt" "$OUTPUT_DIR/vulns/email/dkim.txt" 2>/dev/null | head -30 || echo "None")</pre>
</div>
</div>

<div class="card">
<div class="ch" onclick="tog(this)"><span class="ct">📡 OOB Interactions (Interactsh)</span>
<span class="cb">$(wc -l < "$OUTPUT_DIR/vulns/oob/confirmed_interactions.txt" 2>/dev/null || echo 0)</span></div>
<div class="cd">
  <pre>$(cat "$OUTPUT_DIR/vulns/oob/confirmed_interactions.txt" 2>/dev/null | head -30 || echo "No OOB interactions detected")</pre>
  <p class="stitle">OOB Domain Used</p>
  <pre>$(cat "$OUTPUT_DIR/vulns/oob/domain.txt" 2>/dev/null || echo "N/A")</pre>
</div>
</div>

<div class="card">
<div class="ch" onclick="tog(this)"><span class="ct">🌍 DNS & Infrastructure</span><span class="cb bi">info</span></div>
<div class="cd">
  <p class="stitle">DNS Records</p>
  <pre>$(head -40 "$OUTPUT_DIR/recon/dns.txt" 2>/dev/null || echo "None")</pre>
  <p class="stitle">Open Ports</p>
  <pre>$(head -30 "$OUTPUT_DIR/recon/open_ports.txt" 2>/dev/null || echo "None")</pre>
</div>
</div>

</div>
<div class="ftr">
  <p>🔍 BugHunter Pro v4.0 &nbsp;|&nbsp; $(date '+%Y-%m-%d') &nbsp;|&nbsp; $DOMAIN</p>
  <p style="margin-top:8px;font-size:.78em;color:#303050">
    ⚠️ Authorized penetration testing & bug bounty use only
  </p>
</div>
<script>
function tog(el){el.parentElement.classList.toggle('open')}
function st(el,id){
  const p=el.closest('.cd');
  p.querySelectorAll('.tab').forEach(t=>t.classList.remove('a'));
  p.querySelectorAll('.tc').forEach(t=>t.classList.remove('a'));
  el.classList.add('a');
  const t=document.getElementById('t'+id);
  if(t)t.classList.add('a');
}
</script>
</body>
</html>
HTMLEOF

  # ── Summary TXT ──────────────────────────────────────
  cat > "$RPT/summary.txt" << SUMEOF

  ═══════════════════════════════════════════════════
    BUGHUNTER PRO v4.0 — FINAL SUMMARY
    Target   : $DOMAIN
    Date     : $(date '+%Y-%m-%d %H:%M:%S')
    Duration : ${DURATION} minutes
    Risk     : $RISK (score: $SCORE)
  ═══════════════════════════════════════════════════

  [RECON]
    Total Subdomains : $TOTAL_SUBS
    Live Hosts       : $LIVE_SUBS
    Total URLs       : $TOTAL_URLS
    JS Files         : $TOTAL_JS
    Parameters       : $TOTAL_PARAMS

  [VULNERABILITIES]
    Critical  : $CRIT
    High      : $HIGH
    Medium    : $MED
    Low       : $LOW
    Total     : $TOTAL_VULNS

  [REPORTS]
    HTML      → $RPT/report.html
    Summary   → $RPT/summary.txt
    Findings  → $OUTPUT_DIR/findings.txt
  ═══════════════════════════════════════════════════
SUMEOF

  cat > "$RPT/report.md" << MDEOF
# BugHunter Pro Report

## Executive Summary

- Target: $DOMAIN
- Date: $(date '+%Y-%m-%d %H:%M:%S')
- Duration: ${DURATION} minutes
- Risk: $RISK
- Score: $SCORE

## Statistics

- Subdomains: $TOTAL_SUBS
- Live hosts: $LIVE_SUBS
- URLs: $TOTAL_URLS
- Parameters: $TOTAL_PARAMS
- JS files: $TOTAL_JS
- Critical: $CRIT
- High: $HIGH
- Medium: $MED
- Low: $LOW
- V4 findings: $V4_FINDINGS
- V4 JS artifacts: $V4_JS
- V4 CSP artifacts: $V4_CSP
- V4 GraphQL artifacts: $V4_GRAPHQL
- V4 SSRF artifacts: $V4_SSRF

## Artifacts

- HTML: $RPT/report.html
- JSON: $RPT/report.json
- CSV: $RPT/report.csv
- TXT: $RPT/summary.txt

## Notes

Findings are pulled from the framework outputs and should be revalidated before submission.
MDEOF

  cat > "$RPT/report.json" << JSONEOF
{
  "domain": "$DOMAIN",
  "generated_at": "$(date '+%Y-%m-%d %H:%M:%S')",
  "duration_minutes": $DURATION,
  "risk": "$RISK",
  "score": $SCORE,
  "stats": {
    "subdomains": $TOTAL_SUBS,
    "live_hosts": $LIVE_SUBS,
    "urls": $TOTAL_URLS,
    "parameters": $TOTAL_PARAMS,
    "js_files": $TOTAL_JS,
    "critical": $CRIT,
    "high": $HIGH,
    "medium": $MED,
    "low": $LOW,
    "total_vulns": $TOTAL_VULNS,
    "v4_findings": $V4_FINDINGS,
    "v4_js_artifacts": $V4_JS,
    "v4_csp_artifacts": $V4_CSP,
    "v4_graphql_artifacts": $V4_GRAPHQL,
    "v4_ssrf_artifacts": $V4_SSRF,
    "v4_api_artifacts": $V4_API
  },
  "reports": {
    "html": "$RPT/report.html",
    "markdown": "$RPT/report.md",
    "json": "$RPT/report.json",
    "csv": "$RPT/report.csv",
    "txt": "$RPT/summary.txt"
  }
}
JSONEOF

  cat > "$RPT/report.csv" << CSVEOF
metric,value
domain,$DOMAIN
generated_at,$(date '+%Y-%m-%d %H:%M:%S')
duration_minutes,$DURATION
risk,$RISK
score,$SCORE
subdomains,$TOTAL_SUBS
live_hosts,$LIVE_SUBS
urls,$TOTAL_URLS
parameters,$TOTAL_PARAMS
js_files,$TOTAL_JS
critical,$CRIT
high,$HIGH
medium,$MED
low,$LOW
total_vulns,$TOTAL_VULNS
v4_findings,$V4_FINDINGS
v4_js_artifacts,$V4_JS
v4_csp_artifacts,$V4_CSP
v4_graphql_artifacts,$V4_GRAPHQL
v4_ssrf_artifacts,$V4_SSRF
v4_api_artifacts,$V4_API
CSVEOF

  log_info "HTML Report → ${CYAN}$RPT/report.html${NC}"
}
