/* WiCrackAgent console JS — live status (WS with polling fallback),
   drag & drop upload, speed chart. */
(function () {
  "usestrict";

  var chart = null;
  var history = [];
  var MAX_POINTS = 60;

  function parseSpeed(text) {
    if (!text || typeof text !== "string") return null;
    var m = text.match(/([\d.]+)\s*([kMGT]?H\/s)?/);
    if (!m) return null;
    var value = parseFloat(m[1]);
    var mult = { "kH/s": 1e3, "MH/s": 1e6, "GH/s": 1e9, "TH/s": 1e12 }[m[2]] || 1;
    return value * mult;
  }

  function fmtSpeed(hz) {
    if (!hz) return "—";
    var units = [["TH/s", 1e12], ["GH/s", 1e9], ["MH/s", 1e6], ["kH/s", 1e3]];
    for (var i = 0; i < units.length; i++) {
      if (hz >= units[i][1]) return (hz / units[i][1]).toFixed(1) + " " + units[i][0];
    }
    return Math.round(hz) + " H/s";
  }

  function updateCards(snap) {
    var set = function (id, html) {
      var el = document.getElementById(id);
      if (el) el.innerHTML = html;
    };
    var running = !snap.stopped;
    set("v-worker",
      '<span class="live-dot"></span>' + (running ? "RUNNING" : "STOPPED"));
    var worker = document.getElementById("v-worker");
    if (worker && worker.parentElement) {
      worker.parentElement.classList.toggle("status-stopped", !running);
    }
    set("v-queue", snap.queue);
    set("v-file", snap.current_file || "-");
    set("v-stage", snap.current_stage || "-");
    set("v-speed", snap.speed || "-");
    set("v-progress", snap.progress || "-");
    set("v-cracked", snap.cracked);
    set("v-failed", snap.failed);
  }

  function pushSpeedPoint(snap) {
    var canvas = document.getElementById("speedChart");
    if (!canvas || !window.WICRACK || !window.WICRACK.hasChart) return;
    var hz = parseSpeed(snap.speed);
    if (hz !== null) {
      history.push(hz);
      if (history.length > MAX_POINTS) history.shift();
    }
    if (!chart) {
      chart = new Chart(canvas.getContext("2d"), {
        type: "line",
        data: {
          labels: history.map(function () { return ""; }),
          datasets: [{
            data: history, borderColor: "#00ff88", borderWidth: 2,
            pointRadius: 0, fill: true,
            backgroundColor: "rgba(0,255,136,.08)", tension: 0.3
          }]
        },
        options: {
          animation: false, plugins: { legend: { display: false } },
          scales: {
            x: { display: false },
            y: { ticks: { color: "#8b949e", callback: function (v) {
                    return fmtSpeed(v).replace(" H/s", "").replace("/s", ""); } },
                 grid: { color: "#21262d" } }
          }
        }
      });
    } else {
      chart.data.labels = history.map(function () { return ""; });
      chart.data.datasets[0].data = history;
      chart.update("none");
    }
  }

  function startPolling() {
    setInterval(function () {
      fetch("/api/v1/status")
        .then(function (r) { return r.json(); })
        .then(function (snap) {
          updateCards(snap);
          pushSpeedPoint(snap);
        })
        .catch(function () { /* server restarting */ });
    }, 3000);
  }

  window.startStatusPolling = function () { startPolling(); };

  function startWebSocket() {
    var proto = location.protocol === "https:" ? "wss://" : "ws://";
    var ws = new WebSocket(proto + location.host + "/ws");
    ws.onmessage = function (event) {
      try {
        var snap = JSON.parse(event.data);
        updateCards(snap);
        pushSpeedPoint(snap);
      } catch (e) { /* ignore malformed frame */ }
    };
    ws.onclose = startPolling;   // graceful fallback
  }

  if (window.WICRACK && window.WICRACK.wsEnabled && window.WebSocket) {
    startWebSocket();
  } else if (document.getElementById("speedChart") ||
             document.getElementById("v-worker")) {
    startPolling();
  }

  /* ---------------- drag & drop upload ---------------- */
  window.setupDragDrop = function (zone, fileInput) {
    if (!zone || !fileInput) return;
    ["dragover", "dragenter"].forEach(function (evt) {
      zone.addEventListener(evt, function (e) {
        e.preventDefault();
        zone.classList.add("drag");
      });
    });
    ["dragleave", "drop"].forEach(function (evt) {
      zone.addEventListener(evt, function (e) {
        e.preventDefault();
        zone.classList.remove("drag");
      });
    });
    zone.addEventListener("drop", function (e) {
      if (e.dataTransfer.files.length) {
        fileInput.files = e.dataTransfer.files;
        if (fileInput.form) fileInput.form.submit();
      }
    });
  };
})();
