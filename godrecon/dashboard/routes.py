"""FastAPI router providing the GODRECON web dashboard.

All dashboard pages are rendered with Jinja2 templates.  The router is
mounted at ``/dashboard`` in the main :func:`~godrecon.api.server.create_app`
factory.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from fastapi import APIRouter, Form, HTTPException, Request, Response
    from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates

    _TEMPLATES_DIR = Path(__file__).parent / "templates"
    _STATIC_DIR = Path(__file__).parent / "static"
    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

    router = APIRouter(prefix="/dashboard", tags=["dashboard"])

    # Mount static files
    if _STATIC_DIR.exists():
        from starlette.staticfiles import StaticFiles as StarletteStaticFiles
        router.mount(
            "/static",
            StarletteStaticFiles(directory=str(_STATIC_DIR)),
            name="dashboard-static",
        )

    # -------------------------------------------------------------------------
    # In-memory stores
    # -------------------------------------------------------------------------
    _targets: Dict[str, Dict[str, Any]] = {}
    _kanban: Dict[str, Any] = {}
    _tags: Dict[str, List[str]] = {}
    _notes: Dict[str, str] = {}
    _bookmarks: List[Dict[str, Any]] = []
    _notifications: List[Dict[str, Any]] = []
    _settings_store: Dict[str, Any] = {}
    _earnings: List[Dict[str, Any]] = []
    _activity_log: List[Dict[str, Any]] = []
    _alerts_config: Dict[str, Any] = {}
    _reports_store: Dict[str, Any] = {}

    def _log_activity(action: str, type_: str = "system", details: str = "", target: str = "") -> None:
        _activity_log.append({
            "id": str(uuid.uuid4()),
            "time": datetime.now(timezone.utc).isoformat(),
            "type": type_,
            "action": action,
            "details": details,
            "target": target,
        })
        if len(_activity_log) > 500:
            _activity_log.pop(0)

    def _add_notification(title: str, type_: str = "info") -> None:
        _notifications.append({
            "id": str(uuid.uuid4()),
            "title": title,
            "type": type_,
            "read": False,
            "time": datetime.now(timezone.utc).strftime("%H:%M"),
        })
        if len(_notifications) > 100:
            _notifications.pop(0)

    # -------------------------------------------------------------------------
    # Helper functions
    # -------------------------------------------------------------------------

    def _get_scan_manager(request: Request) -> Any:
        return getattr(request.app.state, "scan_manager", None)

    def _get_all_scans(scan_manager: Any) -> List[Dict[str, Any]]:
        if scan_manager is None:
            return []
        records = scan_manager.list_scans()
        return [_record_to_dict(r) for r in records]

    def _record_to_dict(record: Any) -> Dict[str, Any]:
        resp = record.to_response()
        findings_count = 0
        status_val = resp.status.value if hasattr(resp.status, "value") else str(resp.status)
        if status_val == "completed":
            try:
                result = record.to_result()
                findings_count = len(result.findings)
            except Exception:
                pass
        return {
            "scan_id": resp.scan_id,
            "target": resp.target,
            "status": resp.status.value if hasattr(resp.status, "value") else str(resp.status),
            "created_at": resp.created_at.isoformat() if resp.created_at else "",
            "started_at": resp.started_at.isoformat() if resp.started_at else None,
            "finished_at": resp.finished_at.isoformat() if resp.finished_at else None,
            "modules_completed": resp.modules_completed,
            "error": resp.error,
            "findings_count": findings_count,
            "risk_score": 0.0,
        }

    def _get_findings_for_scan(scan_manager: Any, scan_id: str) -> List[Dict[str, Any]]:
        if scan_manager is None:
            return []
        record = scan_manager.get(scan_id)
        if record is None:
            return []
        try:
            result = record.to_result()
            return [
                {
                    "title": getattr(f, "title", ""),
                    "severity": getattr(f, "severity", "info"),
                    "category": getattr(f, "category", ""),
                    "description": getattr(f, "description", ""),
                    "target": getattr(f, "target", ""),
                    "module": getattr(f, "module", ""),
                    "evidence": getattr(f, "evidence", ""),
                    "remediation": getattr(f, "remediation", ""),
                }
                for f in result.findings
            ]
        except Exception:
            return []

    def _load_config_for_display() -> Dict[str, Any]:
        try:
            from godrecon.core.config import load_config
            cfg = load_config()
            data = cfg.model_dump()
            if "api_keys" in data:
                data["api_keys"] = {k: "***" if v else "" for k, v in data["api_keys"].items()}
            return data
        except Exception:
            return {}

    def _generate_report_content(scan_manager: Any, scan_id: Optional[str], fmt: str, options: Dict[str, Any]) -> str:
        """Generate report content as a string."""
        lines = []
        if fmt == "json":
            data: Dict[str, Any] = {"generated_at": datetime.now(timezone.utc).isoformat(), "findings": []}
            if scan_manager:
                scan_ids = [scan_id] if scan_id else [r.scan_id for r in scan_manager.list_scans()]
                for sid in scan_ids:
                    data["findings"].extend(_get_findings_for_scan(scan_manager, sid))
            return json.dumps(data, indent=2)
        elif fmt == "csv":
            lines.append("severity,title,category,module,target,description")
            if scan_manager:
                scan_ids = [scan_id] if scan_id else [r.scan_id for r in scan_manager.list_scans()]
                for sid in scan_ids:
                    for f in _get_findings_for_scan(scan_manager, sid):
                        lines.append(f'"{f["severity"]}","{f["title"]}","{f["category"]}","{f["module"]}","{f["target"]}","{f["description"][:100]}"')
            return "\n".join(lines)
        else:  # markdown / html
            lines.append("# GODRECON Security Report")
            lines.append(f"\nGenerated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n")
            if options.get("include_exec"):
                lines.append("## Executive Summary\n")
                total = 0
                if scan_manager:
                    scan_ids = [scan_id] if scan_id else [r.scan_id for r in scan_manager.list_scans()]
                    for sid in scan_ids:
                        total += len(_get_findings_for_scan(scan_manager, sid))
                lines.append(f"This report covers **{total}** findings discovered during reconnaissance.\n")
            if options.get("include_vulns"):
                lines.append("## Vulnerabilities\n")
                if scan_manager:
                    scan_ids = [scan_id] if scan_id else [r.scan_id for r in scan_manager.list_scans()]
                    for sid in scan_ids:
                        for f in _get_findings_for_scan(scan_manager, sid):
                            lines.append(f"### [{f['severity'].upper()}] {f['title']}")
                            if f.get("description"):
                                lines.append(f"\n{f['description']}\n")
                            if f.get("remediation") and options.get("include_remediation"):
                                lines.append(f"\n**Remediation:** {f['remediation']}\n")
                            lines.append("---\n")
            return "\n".join(lines)

    # =========================================================================
    # EXISTING ROUTES (preserved)
    # =========================================================================

    @router.get("/", response_class=HTMLResponse, summary="Dashboard home")
    async def dashboard_home(request: Request) -> HTMLResponse:
        scan_manager = _get_scan_manager(request)
        scans = _get_all_scans(scan_manager)
        recent = scans[:5]
        total_scans = len(scans)
        active_scans = sum(1 for s in scans if s["status"] in ("running", "pending"))
        total_findings = sum(s["findings_count"] for s in scans)
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "recent_scans": recent,
                "total_scans": total_scans,
                "active_scans": active_scans,
                "total_findings": total_findings,
            },
        )

    @router.get("/scans", response_class=HTMLResponse, summary="Scan history")
    async def dashboard_scans(request: Request) -> HTMLResponse:
        scan_manager = _get_scan_manager(request)
        scans = _get_all_scans(scan_manager)
        return templates.TemplateResponse("scans.html", {"request": request, "scans": scans})

    @router.get("/scans/{scan_id}", response_class=HTMLResponse, summary="Scan detail")
    async def dashboard_scan_detail(request: Request, scan_id: str) -> HTMLResponse:
        scan_manager = _get_scan_manager(request)
        if scan_manager is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        record = scan_manager.get(scan_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
        scan = _record_to_dict(record)
        findings = _get_findings_for_scan(scan_manager, scan_id)
        module_breakdown: List[Dict[str, Any]] = []
        try:
            result = record.to_result()
            for mod_name, mod_result in (result.module_results or {}).items():
                count = 0
                if isinstance(mod_result, dict):
                    count = mod_result.get("findings_count", 0)
                elif hasattr(mod_result, "findings_count"):
                    count = mod_result.findings_count or 0
                elif hasattr(mod_result, "findings"):
                    count = len(mod_result.findings or [])
                module_breakdown.append({"module": mod_name, "findings": count})
        except Exception:
            pass
        return templates.TemplateResponse(
            "scan_detail.html",
            {"request": request, "scan": scan, "findings": findings, "module_breakdown": module_breakdown},
        )

    @router.get("/findings", response_class=HTMLResponse, summary="Findings browser")
    async def dashboard_findings(
        request: Request,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        module: Optional[str] = None,
        target: Optional[str] = None,
    ) -> HTMLResponse:
        scan_manager = _get_scan_manager(request)
        all_findings: List[Dict[str, Any]] = []
        if scan_manager is not None:
            for record in scan_manager.list_scans():
                scan_findings = _get_findings_for_scan(scan_manager, record.scan_id)
                for f in scan_findings:
                    f["scan_id"] = record.scan_id
                    f["scan_target"] = record.target
                all_findings.extend(scan_findings)
        if severity:
            all_findings = [f for f in all_findings if f["severity"].lower() == severity.lower()]
        if category:
            all_findings = [f for f in all_findings if f["category"].lower() == category.lower()]
        if module:
            all_findings = [f for f in all_findings if f["module"].lower() == module.lower()]
        if target:
            all_findings = [f for f in all_findings if target.lower() in f.get("scan_target", "").lower()]
        return templates.TemplateResponse(
            "findings.html",
            {"request": request, "findings": all_findings, "filters": {"severity": severity, "category": category, "module": module, "target": target}},
        )

    @router.get("/surface", response_class=HTMLResponse, summary="Attack surface map")
    async def dashboard_surface(request: Request) -> HTMLResponse:
        scan_manager = _get_scan_manager(request)
        surface_data: Dict[str, Any] = {"subdomains": [], "ips": [], "ports": [], "technologies": []}
        if scan_manager is not None:
            for record in scan_manager.list_scans():
                status_val = record.status.value if hasattr(record.status, "value") else str(record.status)
                if status_val != "completed":
                    continue
                try:
                    result = record.to_result()
                    mod_results = result.module_results or {}
                    sub_res = mod_results.get("subdomains")
                    if sub_res:
                        data = getattr(sub_res, "data", None) or (sub_res.get("data") if isinstance(sub_res, dict) else None) or {}
                        subs = data.get("subdomains", []) if isinstance(data, dict) else []
                        for s in subs:
                            if s not in surface_data["subdomains"]:
                                surface_data["subdomains"].append(s)
                    tech_res = mod_results.get("tech")
                    if tech_res:
                        data = getattr(tech_res, "data", None) or (tech_res.get("data") if isinstance(tech_res, dict) else None) or {}
                        if isinstance(data, dict):
                            for url_data in data.values():
                                if isinstance(url_data, dict):
                                    for tech in url_data.get("technologies", []):
                                        if tech not in surface_data["technologies"]:
                                            surface_data["technologies"].append(tech)
                except Exception:
                    pass
        return templates.TemplateResponse("surface.html", {"request": request, "surface_data": surface_data})

    @router.get("/settings", response_class=HTMLResponse, summary="Settings page")
    async def dashboard_settings(request: Request) -> HTMLResponse:
        config_data = _load_config_for_display()
        return templates.TemplateResponse("settings.html", {"request": request, "config": config_data})

    @router.post("/settings", response_class=HTMLResponse, summary="Save settings")
    async def dashboard_settings_save(request: Request) -> HTMLResponse:
        config_data = _load_config_for_display()
        return templates.TemplateResponse(
            "settings.html",
            {"request": request, "config": config_data, "message": "Settings noted. Update config.yaml to persist changes."},
        )

    # =========================================================================
    # NEW PAGE ROUTES
    # =========================================================================

    @router.get("/targets", response_class=HTMLResponse)
    async def dashboard_targets(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("targets.html", {"request": request})

    @router.get("/subdomains", response_class=HTMLResponse)
    async def dashboard_subdomains(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("subdomains.html", {"request": request})

    @router.get("/vulnerabilities", response_class=HTMLResponse)
    async def dashboard_vulnerabilities(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("vulnerabilities.html", {"request": request})

    @router.get("/chains", response_class=HTMLResponse)
    async def dashboard_chains(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("chains.html", {"request": request})

    @router.get("/secrets", response_class=HTMLResponse)
    async def dashboard_secrets(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("secrets.html", {"request": request})

    @router.get("/kanban", response_class=HTMLResponse)
    async def dashboard_kanban(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("kanban.html", {"request": request})

    @router.get("/reports", response_class=HTMLResponse)
    async def dashboard_reports(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("reports.html", {"request": request})

    @router.get("/ai-validation", response_class=HTMLResponse)
    async def dashboard_ai_validation(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("ai_validation.html", {"request": request})

    @router.get("/bounty-matcher", response_class=HTMLResponse)
    async def dashboard_bounty_matcher(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("bounty_matcher.html", {"request": request})

    @router.get("/analytics", response_class=HTMLResponse)
    async def dashboard_analytics(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("analytics.html", {"request": request})

    @router.get("/analytics/trends", response_class=HTMLResponse)
    async def dashboard_analytics_trends(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("analytics.html", {"request": request, "active_tab": "trends"})

    @router.get("/analytics/severity", response_class=HTMLResponse)
    async def dashboard_analytics_severity(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("analytics.html", {"request": request, "active_tab": "severity"})

    @router.get("/analytics/compare", response_class=HTMLResponse)
    async def dashboard_analytics_compare(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("analytics.html", {"request": request, "active_tab": "targets"})

    @router.get("/analytics/ai-insights", response_class=HTMLResponse)
    async def dashboard_analytics_ai_insights(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("analytics.html", {"request": request})

    @router.get("/analytics/earnings", response_class=HTMLResponse)
    async def dashboard_analytics_earnings(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("analytics.html", {"request": request, "active_tab": "earnings"})

    @router.get("/leaderboard", response_class=HTMLResponse)
    async def dashboard_leaderboard(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("leaderboard.html", {"request": request})

    @router.get("/activity-log", response_class=HTMLResponse)
    async def dashboard_activity_log(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("activity_log.html", {"request": request})

    @router.get("/alerts", response_class=HTMLResponse)
    async def dashboard_alerts(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("alerts.html", {"request": request})

    # =========================================================================
    # SCANNER SUB-PAGES
    # =========================================================================

    _SCANNER_META: Dict[str, Dict[str, str]] = {
        "nuclei": {"name": "Nuclei Scanner", "icon": "🔬", "desc": "Nuclei template-based vulnerability scanning", "module": "nuclei", "aliases": "nuclei_scan"},
        "cloud": {"name": "Cloud Misconfig", "icon": "☁️", "desc": "Cloud misconfiguration findings (S3, Azure, GCP, Firebase)", "module": "cloud", "aliases": "cloud_misconfig,s3,azure"},
        "auth": {"name": "Auth Scan", "icon": "🔐", "desc": "Authentication bypass and weak credential findings", "module": "auth", "aliases": "auth_scan,authentication"},
        "waf": {"name": "WAF Detection", "icon": "🛡️", "desc": "Web Application Firewall detection and bypass findings", "module": "waf", "aliases": "waf_detection,waf_bypass"},
        "fuzzing": {"name": "Fuzzing", "icon": "🎲", "desc": "HTTP parameter and path fuzzing results", "module": "fuzzing", "aliases": "fuzz,directory_fuzzing"},
        "cve": {"name": "CVE/Exploits", "icon": "💀", "desc": "Known CVE and exploit findings", "module": "cve", "aliases": "cve_scan,exploits,known_vuln"},
        "email": {"name": "Email Security", "icon": "📧", "desc": "SPF, DKIM, DMARC and email security findings", "module": "email", "aliases": "email_security,spf,dmarc"},
        "supply-chain": {"name": "Supply Chain", "icon": "📦", "desc": "Supply chain and dependency vulnerability findings", "module": "supply_chain", "aliases": "dependency,npm,pypi"},
        "mobile-api": {"name": "Mobile API", "icon": "📱", "desc": "Mobile API endpoint vulnerability findings", "module": "mobile_api", "aliases": "mobile,api_scan"},
        "business-logic": {"name": "Business Logic", "icon": "🏢", "desc": "Business logic vulnerability findings", "module": "business_logic", "aliases": "logic,workflow"},
        "multi-region": {"name": "Multi-Region", "icon": "🌍", "desc": "Multi-region scan comparison results", "module": "multi_region", "aliases": "region,geo"},
        "cache-poisoning": {"name": "Cache Poisoning", "icon": "☣️", "desc": "HTTP cache poisoning vulnerability findings", "module": "cache_poisoning", "aliases": "cache,web_cache"},
        "browser-extensions": {"name": "Browser Extensions", "icon": "🧩", "desc": "Browser extension vulnerability findings", "module": "browser_extensions", "aliases": "browser,extension"},
        "scan-diff": {"name": "Scan Diff", "icon": "🔄", "desc": "Differential scan comparison results", "module": "scan_diff", "aliases": "diff,delta"},
        "smart-params": {"name": "Smart Params", "icon": "🧠", "desc": "Smart parameter discovery and injection findings", "module": "smart_params", "aliases": "params,parameter"},
        "oob": {"name": "OOB Callbacks", "icon": "📡", "desc": "Out-of-band interaction findings", "module": "oob", "aliases": "oob_callbacks,ssrf,xxe"},
        "github-dorking": {"name": "GitHub Dorking", "icon": "🐙", "desc": "GitHub secret scanning and dorking results", "module": "github_dorking", "aliases": "git_dorking,github_secrets"},
    }

    @router.get("/scanners/nuclei", response_class=HTMLResponse)
    async def scanner_nuclei(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("scanners/nuclei.html", {"request": request})

    @router.get("/scanners/cloud", response_class=HTMLResponse)
    async def scanner_cloud(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("scanners/cloud.html", {"request": request})

    @router.get("/scanners/dns", response_class=HTMLResponse)
    async def scanner_dns(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("scanners/dns.html", {"request": request})

    @router.get("/scanners/ssl", response_class=HTMLResponse)
    async def scanner_ssl(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("scanners/ssl.html", {"request": request})

    @router.get("/scanners/passive-recon", response_class=HTMLResponse)
    async def scanner_passive_recon(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("scanners/passive_recon.html", {"request": request})

    @router.get("/scanners/wayback", response_class=HTMLResponse)
    async def scanner_wayback(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("scanners/wayback.html", {"request": request})

    @router.get("/scanners/github-dorking", response_class=HTMLResponse)
    async def scanner_github_dorking(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("scanners/github_dorking.html", {"request": request})

    # Generic scanner route for all others
    _GENERIC_SCANNERS = ["auth", "waf", "fuzzing", "cve", "email", "supply-chain",
                         "mobile-api", "business-logic", "multi-region", "cache-poisoning",
                         "browser-extensions", "scan-diff", "smart-params", "oob"]

    def _make_generic_scanner_route(slug: str):
        meta = _SCANNER_META.get(slug, {})

        async def _route(request: Request) -> HTMLResponse:
            return templates.TemplateResponse(
                "scanners/scanner_generic.html",
                {
                    "request": request,
                    "scanner_name": meta.get("name", slug.title()),
                    "scanner_icon": meta.get("icon", "🔬"),
                    "scanner_desc": meta.get("desc", ""),
                    "scanner_module": meta.get("module", slug.replace("-", "_")),
                    "scanner_module_aliases": meta.get("aliases", ""),
                },
            )

        _route.__name__ = f"scanner_{slug.replace('-', '_')}"
        return _route

    for _slug in _GENERIC_SCANNERS:
        _route_fn = _make_generic_scanner_route(_slug)
        router.add_api_route(
            f"/scanners/{_slug}",
            _route_fn,
            response_class=HTMLResponse,
            methods=["GET"],
        )

    # =========================================================================
    # API ENDPOINTS (AJAX)
    # =========================================================================

    # --- Targets ---
    @router.get("/api/targets")
    async def api_get_targets(request: Request) -> JSONResponse:
        scan_manager = _get_scan_manager(request)
        scans = _get_all_scans(scan_manager)
        # Enrich targets with scan data
        enriched = []
        for tid, t in _targets.items():
            target_scans = [s for s in scans if s["target"] == t["domain"]]
            last_scan = max((s["created_at"] for s in target_scans), default=None)
            findings_count = sum(s["findings_count"] for s in target_scans)
            status = target_scans[-1]["status"] if target_scans else "pending"
            enriched.append({**t, "last_scan": last_scan, "findings_count": findings_count, "status": status})
        return JSONResponse({"targets": enriched})

    @router.post("/api/targets")
    async def api_add_target(request: Request) -> JSONResponse:
        data = await request.json()
        tid = str(uuid.uuid4())
        _targets[tid] = {
            "id": tid,
            "domain": data.get("domain", ""),
            "mode": data.get("mode", "standard"),
            "tags": data.get("tags", []),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        _log_activity(f"Added target {data.get('domain')}", "target", target=data.get("domain", ""))
        return JSONResponse({"id": tid, **_targets[tid]})

    @router.delete("/api/targets/{target_id}")
    async def api_delete_target(target_id: str) -> JSONResponse:
        if target_id not in _targets:
            raise HTTPException(status_code=404, detail="Target not found")
        domain = _targets[target_id].get("domain", "")
        del _targets[target_id]
        _log_activity(f"Deleted target {domain}", "target", target=domain)
        return JSONResponse({"ok": True})

    # --- Kanban ---
    @router.get("/api/kanban")
    async def api_get_kanban() -> JSONResponse:
        return JSONResponse({"cards": _kanban})

    @router.post("/api/kanban")
    async def api_save_kanban(request: Request) -> JSONResponse:
        data = await request.json()
        _kanban.update(data.get("cards", data.get("state", {})))
        return JSONResponse({"ok": True})

    # --- Notifications ---
    @router.get("/api/notifications")
    async def api_get_notifications() -> JSONResponse:
        return JSONResponse({"notifications": _notifications})

    @router.post("/api/notifications")
    async def api_add_notification(request: Request) -> JSONResponse:
        data = await request.json()
        _add_notification(data.get("title", ""), data.get("type", "info"))
        return JSONResponse({"ok": True})

    # --- Settings ---
    @router.post("/api/settings")
    async def api_save_settings(request: Request) -> JSONResponse:
        data = await request.json()
        _settings_store.update(data)
        _log_activity("Settings updated", "system")
        return JSONResponse({"ok": True})

    # --- Activity log ---
    @router.get("/api/activity-log")
    async def api_activity_log() -> JSONResponse:
        return JSONResponse({"entries": list(reversed(_activity_log))})

    @router.post("/api/activity-log/clear")
    async def api_clear_activity_log() -> JSONResponse:
        _activity_log.clear()
        return JSONResponse({"ok": True})

    # --- Alerts ---
    @router.get("/api/alerts")
    async def api_get_alerts() -> JSONResponse:
        return JSONResponse({"config": _alerts_config})

    @router.post("/api/alerts")
    async def api_save_alerts(request: Request) -> JSONResponse:
        data = await request.json()
        _alerts_config.update(data.get("config", data))
        _log_activity("Alert configuration updated", "system")
        return JSONResponse({"ok": True})

    @router.post("/api/alerts/test")
    async def api_test_alert(request: Request) -> JSONResponse:
        data = await request.json()
        channel = data.get("channel", "unknown")
        _log_activity(f"Test alert sent to {channel}", "system")
        return JSONResponse({"ok": True, "message": f"Test alert sent to {channel}"})

    # --- Earnings ---
    @router.get("/api/earnings")
    async def api_get_earnings() -> JSONResponse:
        return JSONResponse({"entries": _earnings})

    @router.post("/api/earnings")
    async def api_save_earnings(request: Request) -> JSONResponse:
        data = await request.json()
        _earnings.clear()
        _earnings.extend(data.get("entries", []))
        return JSONResponse({"ok": True})

    # --- Reports ---
    @router.post("/api/reports/generate")
    async def api_generate_report(request: Request) -> JSONResponse:
        data = await request.json()
        scan_manager = _get_scan_manager(request)
        scan_id = data.get("scan_id") or None
        fmt = data.get("format", "markdown")
        options = {k: data.get(k, True) for k in ["include_exec", "include_vulns", "include_subs", "include_remediation"]}
        content = _generate_report_content(scan_manager, scan_id, fmt, options)
        report_id = str(uuid.uuid4())
        filename = f"godrecon-report-{report_id[:8]}.{fmt if fmt != 'markdown' else 'md'}"
        _reports_store[report_id] = {
            "id": report_id,
            "filename": filename,
            "format": fmt,
            "content": content,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        _log_activity(f"Generated {fmt} report", "report")
        return JSONResponse({"id": report_id, "filename": filename, "content": content})

    @router.get("/api/reports/history")
    async def api_report_history() -> JSONResponse:
        reports = [{"id": r["id"], "filename": r["filename"], "format": r["format"], "created_at": r["created_at"]} for r in _reports_store.values()]
        return JSONResponse({"reports": sorted(reports, key=lambda x: x["created_at"], reverse=True)})

    @router.get("/api/reports/{report_id}")
    async def api_get_report(report_id: str) -> JSONResponse:
        if report_id not in _reports_store:
            raise HTTPException(status_code=404, detail="Report not found")
        return JSONResponse(_reports_store[report_id])

    # --- Scan stats aggregated ---
    @router.get("/api/scan-stats")
    async def api_scan_stats(request: Request) -> JSONResponse:
        scan_manager = _get_scan_manager(request)
        scans = _get_all_scans(scan_manager)
        sev_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for scan in scans:
            if scan["status"] == "completed":
                findings = _get_findings_for_scan(scan_manager, scan["scan_id"])
                for f in findings:
                    s = f.get("severity", "info").lower()
                    if s in sev_counts:
                        sev_counts[s] += 1
        return JSONResponse({
            "total_scans": len(scans),
            "active_scans": sum(1 for s in scans if s["status"] in ("running", "pending")),
            "completed_scans": sum(1 for s in scans if s["status"] == "completed"),
            "total_findings": sum(s["findings_count"] for s in scans),
            "severity_counts": sev_counts,
        })

    # --- Tags / Notes / Bookmarks ---
    @router.get("/api/tags")
    async def api_get_tags() -> JSONResponse:
        return JSONResponse({"tags": _tags})

    @router.post("/api/tags")
    async def api_save_tags(request: Request) -> JSONResponse:
        data = await request.json()
        _tags.update(data.get("tags", {}))
        return JSONResponse({"ok": True})

    @router.get("/api/notes")
    async def api_get_notes() -> JSONResponse:
        return JSONResponse({"notes": _notes})

    @router.post("/api/notes")
    async def api_save_notes(request: Request) -> JSONResponse:
        data = await request.json()
        _notes.update(data.get("notes", {}))
        return JSONResponse({"ok": True})

    @router.get("/api/bookmarks")
    async def api_get_bookmarks() -> JSONResponse:
        return JSONResponse({"bookmarks": _bookmarks})

    @router.post("/api/bookmarks")
    async def api_add_bookmark(request: Request) -> JSONResponse:
        data = await request.json()
        _bookmarks.append({**data, "id": str(uuid.uuid4()), "created_at": datetime.now(timezone.utc).isoformat()})
        return JSONResponse({"ok": True})

    @router.delete("/api/bookmarks/{bookmark_id}")
    async def api_delete_bookmark(bookmark_id: str) -> JSONResponse:
        global _bookmarks
        _bookmarks = [b for b in _bookmarks if b.get("id") != bookmark_id]
        return JSONResponse({"ok": True})

    # --- SSE scan stream ---
    @router.get("/api/scan-stream/{scan_id}")
    async def api_scan_stream(request: Request, scan_id: str) -> Response:
        scan_manager = _get_scan_manager(request)

        async def event_generator():
            if scan_manager is None:
                yield 'data: {"type":"error","message":"Scan manager not available"}\n\n'
                return
            record = scan_manager.get(scan_id)
            if record is None:
                yield f'data: {{"type":"error","message":"Scan {scan_id} not found"}}\n\n'
                return
            for _ in range(60):
                if await request.is_disconnected():
                    break
                try:
                    resp = record.to_response()
                    status = resp.status.value if hasattr(resp.status, "value") else str(resp.status)
                    modules = resp.modules_completed or []
                    yield f'data: {{"type":"info","message":"Status: {status}, Modules: {len(modules)} completed"}}\n\n'
                    if status in ("completed", "failed"):
                        yield f'data: {{"type":"{"success" if status == "completed" else "error"}","message":"Scan {status}"}}\n\n'
                        break
                except Exception as e:
                    yield f'data: {{"type":"error","message":"{str(e)}"}}\n\n'
                    break
                import asyncio
                await asyncio.sleep(2)

        return Response(
            event_generator(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # =========================================================================
    # REPORTS GENERATE (form POST)
    # =========================================================================
    @router.post("/reports/generate")
    async def dashboard_reports_generate(request: Request) -> HTMLResponse:
        return RedirectResponse("/dashboard/reports", status_code=302)

except ImportError:
    from unittest.mock import MagicMock
    router = MagicMock()  # type: ignore[assignment]
