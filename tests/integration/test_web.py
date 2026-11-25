"""Web console integration: auth, upload, config persistence, jobs, API."""

import io
import time


def test_auth_gate_redirects(client):
    r = client.get("/")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_login_wrong_password(client):
    r = client.post("/login", data={"password": "nope"})
    html = r.get_data(as_text=True)
    assert "Wrong password" in html


def test_login_success_and_logout(client):
    r = client.post("/login", data={"password": "testpw"})
    assert r.status_code == 302
    r = client.get("/")
    assert r.status_code == 200
    assert "WiCrackAgent" in r.get_data(as_text=True)
    r = client.get("/logout")
    assert r.status_code == 302
    assert client.get("/").status_code == 302


def test_dashboard_renders(client):
    client.post("/login", data={"password": "testpw"})
    html = client.get("/").get_data(as_text=True)
    assert "v-worker" in html and "Recent cracks" in html


def test_upload_accept_and_reject(client):
    client.post("/login", data={"password": "testpw"})
    r = client.post(
        "/upload",
        data={"capture": (io.BytesIO(b"fake pcap bytes"), "net.cap")},
        content_type="multipart/form-data",
    )
    assert "Uploaded: net.cap" in r.get_data(as_text=True)

    r = client.post(
        "/upload",
        data={"capture": (io.BytesIO(b"x"), "evil.exe")},
        content_type="multipart/form-data",
    )
    assert "Only .cap" in r.get_data(as_text=True)

    r = client.get("/upload")
    assert "net.cap" in r.get_data(as_text=True)


def test_upload_delete(client, settings):
    client.post("/login", data={"password": "testpw"})
    target = settings.uploads_dir / "delme.cap"
    target.write_bytes(b"x")
    r = client.get("/upload?del=delme.cap")
    assert "Deleted: delme.cap" in r.get_data(as_text=True)
    assert not target.exists()


def test_config_save_persists_and_unchecks(client, settings):
    client.post("/login", data={"password": "testpw"})
    r = client.post(
        "/config",
        data={
            "wordlists": "/tmp/wl1, /tmp/wl2",
            "rules": "/usr/share/hashcat/rules/best64.rule",
            "rules_ortra": str(settings.rules_ortra),
            "workload": "4",
            "temp_abort": "80",
            "auto_ok_hours": "1.5",
            "enable_ortra": "on",
            "enable_combinator": "on",
            "heavy_window": "22:00-06:00",
            "filter_essids": "HomeWiFi,Office",
            "filter_mode": "include",
        },
    )
    html = r.get_data(as_text=True)
    assert "Settings saved" in html
    assert settings.workload == 4
    assert settings.temp_abort == 80
    assert settings.enable_ortra is True
    assert settings.enable_kbwalks is False  # unchecked -> False
    assert settings.heavy_window == "22:00-06:00"
    assert settings.filter_essids == ["HomeWiFi", "Office"]
    assert settings.web_state_path.exists()  # persisted
    assert "22:00-06:00" in html  # re-rendered


def test_config_invalid_number_shows_error(client, settings):
    client.post("/login", data={"password": "testpw"})
    r = client.post("/config", data={"temp_abort": "notanumber", "workload": "3"})
    assert "Invalid value" in r.get_data(as_text=True)


def test_jobs_start_and_worker_consumes(client, settings, store):
    client.post("/login", data={"password": "testpw"})
    (settings.uploads_dir / "jobtest.cap").write_bytes(b"x")
    r = client.post("/jobs/start")
    assert r.status_code == 302
    # qsize() drops as soon as the worker picks a job — wait for the run row
    deadline = time.time() + 5
    while time.time() < deadline:
        runs = [dict(r) for r in store.recent_runs()]
        if any(r["file"] == "jobtest.cap" for r in runs):
            break
        time.sleep(0.2)
    assert client.get("/api/v1/status").get_json()["queue"] == 0
    assert any(r["file"] == "jobtest.cap" for r in runs)


def test_jobs_stop(client):
    client.post("/login", data={"password": "testpw"})
    client.post("/jobs/stop")
    assert client.get("/api/v1/status").get_json()["stopped"] is True
    client.post("/jobs/start")  # resume clears the flag


def test_api_endpoints(client):
    client.post("/login", data={"password": "testpw"})
    status = client.get("/api/v1/status")
    assert status.status_code == 200 and "queue" in status.get_json()
    jobs = client.get("/api/v1/jobs")
    assert jobs.status_code == 200 and "runs" in jobs.get_json()
    bad = client.post("/api/v1/jobs", json={"action": "bogus"})
    assert bad.status_code == 400
    ok = client.post("/api/v1/jobs", json={"action": "stop"})
    assert ok.get_json()["ok"] is True


def test_results_pages_and_downloads(client, store):
    from wicrack.core.models import CrackResult
    from wicrack.selftest import make_test_22000

    line, _ = make_test_22000()
    head = line.rsplit(":", 1)[0]
    result = CrackResult.from_pot_line(f"{head}:FoundKey123", stage="A")
    store.add_results([result])

    client.post("/login", data={"password": "testpw"})
    html = client.get("/results").get_data(as_text=True)
    assert "FoundKey123" in html
    csv = client.get("/results/download/csv")
    assert csv.status_code == 200 and "FoundKey123" in csv.get_data(as_text=True)
    txt = client.get("/results/download/txt")
    assert txt.status_code in (200, 302)
    report = client.get("/results/download/report")
    assert report.status_code == 200
    assert "Assessment" in report.get_data(as_text=True)
