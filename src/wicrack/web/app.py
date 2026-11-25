"""Flask application factory for the live web console."""

from __future__ import annotations

import hmac
import json
import time
from pathlib import Path

from flask import Flask, redirect, render_template, request, send_file, session, url_for
from loguru import logger

from wicrack import __version__
from wicrack.capture.parser import CAP_EXTENSIONS, list_capture_files
from wicrack.core.jobqueue import JobManager
from wicrack.core.store import Store
from wicrack.web.api import api_bp


def create_app(
    settings, job_manager: JobManager | None = None, store: Store | None = None
) -> Flask:
    """Build the Flask app; engines/manager can be injected for tests."""
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = settings.ensure_session_secret()
    app.config.update(
        MAX_CONTENT_LENGTH=settings.max_upload_mb * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    settings.ensure_dirs()
    store = store or Store(settings.db_path)
    if job_manager is None:
        from wicrack.engines.selector import select_engine

        job_manager = JobManager(settings, select_engine(settings), store=store)
    mgr = job_manager
    mgr.start_worker()

    app.extensions["wicrack_settings"] = settings
    app.extensions["wicrack_manager"] = mgr
    app.extensions["wicrack_store"] = store
    app.register_blueprint(api_bp)

    try:
        from flask_sock import Sock

        sock = Sock(app)
    except ImportError:  # graceful degradation: JS falls back to polling
        sock = None

    if sock is not None:

        @sock.route("/ws")
        def ws(sock_conn):  # pragma: no cover - exercised manually
            """Push status snapshots to the browser once per second."""
            while True:
                try:
                    sock_conn.send(json.dumps(mgr.snapshot()))
                    time.sleep(1)
                except Exception:
                    break

    # ---------------------------------------------------------- auth gate
    @app.before_request
    def auth_gate():
        allowed = {"login", "static"}
        if request.endpoint in allowed or request.endpoint is None:
            return None
        if not session.get("ok"):
            return redirect(url_for("login"))

    @app.context_processor
    def inject_globals():
        return dict(version=__version__, engine=mgr.engine.name, path=request.path)

    # -------------------------------------------------------------- login
    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = ""
        if request.method == "POST":
            supplied = request.form.get("password", "")
            try:
                ok = hmac.compare_digest(supplied, settings.web_password)
            except TypeError:
                ok = False
            if ok:
                session["ok"] = True
                return redirect(url_for("dashboard"))
            error = "Wrong password"
            logger.warning("Failed web console login")
        return render_template("login.html", error=error)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ---------------------------------------------------------- dashboard
    @app.route("/")
    def dashboard():
        return render_template(
            "dashboard.html",
            snap=mgr.snapshot(),
            recent=[dict(r) for r in store.recent(15)],
            ws_enabled=sock is not None,
        )

    # ------------------------------------------------------------- upload
    @app.route("/upload", methods=["GET", "POST"])
    def upload():
        message = ""
        if request.method == "POST":
            uploaded = request.files.get("capture")
            if uploaded and uploaded.filename:
                from werkzeug.utils import secure_filename

                name = secure_filename(uploaded.filename)
                if name.lower().endswith(CAP_EXTENSIONS):
                    dest = settings.uploads_dir / name
                    settings.uploads_dir.mkdir(parents=True, exist_ok=True)
                    uploaded.save(dest)
                    logger.info("[web] capture uploaded: {}", name)
                    message = f"Uploaded: {name}"
                else:
                    message = "Only .cap / .pcap / .pcapng files are allowed"
            else:
                message = "No file selected"
        if request.args.get("del"):
            raw = request.args.get("del") or ""
            name = Path(raw).name
            target = settings.uploads_dir / name
            if name and name.lower().endswith(CAP_EXTENSIONS) and target.is_file():
                target.unlink()
                message = f"Deleted: {name}"
        files = [
            dict(name=p.name, size_kb=p.stat().st_size // 1024)
            for p in list_capture_files(settings.uploads_dir)
        ]
        return render_template(
            "upload.html", files=files, message=message, max_mb=settings.max_upload_mb
        )

    # ------------------------------------------------------------- config
    @app.route("/config", methods=["GET", "POST"])
    def config():
        message = ""
        if request.method == "POST":
            form = request.form

            def checkbox(key: str) -> bool:
                return key in form

            try:
                settings.wordlists = form.get("wordlists", "")
                settings.rules = form.get("rules", settings.rules)
                settings.rules_ortra = form.get("rules_ortra", settings.rules_ortra)
                settings.workload = int(form.get("workload", settings.workload))
                settings.optimized = checkbox("optimized")
                settings.temp_abort = int(form.get("temp_abort", settings.temp_abort))
                settings.auto_ok_hours = float(form.get("auto_ok_hours", settings.auto_ok_hours))
                settings.enable_ortra = checkbox("enable_ortra")
                settings.enable_kbwalks = checkbox("enable_kbwalks")
                settings.enable_mangler = checkbox("enable_mangler")
                settings.enable_mask_learning = checkbox("enable_mask_learning")
                settings.enable_combinator = checkbox("enable_combinator")
                settings.enable_three_word = checkbox("enable_three_word")
                settings.enable_brain = checkbox("enable_brain")
                settings.web_auto_approve_heavy = checkbox("web_auto_approve_heavy")
                settings.heavy_window = form.get("heavy_window", "").strip() or None
                settings.telegram_token = form.get("telegram_token", "").strip()
                settings.telegram_chat_id = form.get("telegram_chat_id", "").strip()
                settings.discord_webhook = form.get("discord_webhook", "").strip()
                settings.filter_essids = form.get("filter_essids", "")
                settings.filter_bssids = form.get("filter_bssids", "")
                settings.filter_mode = form.get("filter_mode", "include")
                new_password = form.get("new_password", "").strip()
                if new_password:
                    settings.change_web_password(new_password)
                settings.save_web_overrides()
                message = "Settings saved (persisted across restarts)"
                logger.info("[web] settings updated from web console")
            except ValueError as exc:
                message = f"Invalid value: {exc}"
        return render_template("config.html", s=settings, message=message)

    # --------------------------------------------------------------- jobs
    @app.route("/jobs")
    def jobs():
        files = list_capture_files(settings.uploads_dir)
        return render_template(
            "jobs.html",
            snap=mgr.snapshot(),
            runs=[dict(r) for r in store.recent_runs(25)],
            uploaded=len(files),
        )

    @app.route("/jobs/start", methods=["POST"])
    def jobs_start():
        files = list_capture_files(settings.uploads_dir)
        if files:
            mgr.resume()
            mgr.submit(files)
        return redirect(url_for("jobs"))

    @app.route("/jobs/stop", methods=["POST"])
    def jobs_stop():
        mgr.stop()
        return redirect(url_for("jobs"))

    # ------------------------------------------------------------ results
    @app.route("/results")
    def results():
        return render_template("results.html", rows=[dict(r) for r in store.all_results()])

    @app.route("/results/download/csv")
    def results_csv():
        import csv as _csv
        import io as _io

        buffer = _io.StringIO()
        writer = _csv.writer(buffer)
        writer.writerow(
            [
                "time",
                "essid",
                "bssid",
                "mode",
                "key",
                "key_len",
                "has_space",
                "only_digits",
                "stage",
            ]
        )
        for r in store.all_results():
            writer.writerow(
                [
                    r["ts"],
                    r["essid"],
                    r["bssid"],
                    r["mode"],
                    r["key"],
                    r["key_len"],
                    r["has_space"],
                    r["only_digits"],
                    r["stage"],
                ]
            )
        report = settings.csv_export_path
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(buffer.getvalue(), encoding="utf-8")
        return send_file(report, as_attachment=True)

    @app.route("/results/download/txt")
    def results_txt():
        if settings.text_report_path.exists():
            return send_file(settings.text_report_path, as_attachment=True)
        return redirect(url_for("results"))

    @app.route("/results/download/report")
    def results_report():
        from wicrack.reporting.html_report import generate_html_report

        path = generate_html_report(store, settings, settings.report_dir / "assessment_report.html")
        return send_file(path, as_attachment=True)

    return app
