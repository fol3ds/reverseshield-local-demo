"""ReverseShield HTTP entry point.

The server is loopback-only. It serves the workbench UI and a legacy metadata
API; the upgraded JSON API lives in ``http_upgrade.py``. Static analysis tools
read target bytes as data; the selected target is never executed on the host. The optional OLLVM sample profile runs deterministic drivers only inside a QEMU micro-VM.

Inputs are loopback HTTP requests and local files; outputs are static JSON or
the browser UI. Uploaded bytes are bounded and never executed. Extend routes
through ``http_upgrade.py`` where possible and keep legacy ELF-only behavior
clearly separated from PE-capable APIs.
"""
from __future__ import annotations

import json
import os
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from analysis import MAX_FILE_BYTES, analyze_elf, has_elf_magic, tool_inventory
from discovery import discover_flatpak_targets, list_flatpak_apps
from samples import ROOT, SAMPLE_ROOT, SAMPLES, get_sample, public_sample

STATIC_ROOT = ROOT / "static"
PORT_START = 8765


class LegacyMetadataHandler(BaseHTTPRequestHandler):
    server_version = "ReverseShieldLocalDemo/0.1"

    def log_message(self, format: str, *args) -> None:
        print("[ReverseShield] request handled")

    def _send(self, body: bytes, content_type: str = "application/json; charset=utf-8", status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, value: dict, status: int = 200) -> None:
        self._send(json.dumps(value, ensure_ascii=False).encode("utf-8"), status=status)

    def _read_body(self, limit: int) -> bytes:
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid Content-Length.") from exc
        if size < 0 or size > limit:
            raise ValueError(f"Request exceeds the {limit // (1024 * 1024)} MiB limit.")
        return self.rfile.read(size)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path in ("/", "/index.html"):
            page = STATIC_ROOT / "index.html"
            if not page.is_file():
                self._json({"error": "Workbench HTML has not been created."}, 500)
                return
            self._send(page.read_bytes(), "text/html; charset=utf-8")
            return
        if path == "/api/status":
            self._json({
                "application": "ReverseShield Local Demo",
                "version": "0.1",
                "mode": "static_only",
                "tools": tool_inventory(),
                "dynamic_analysis": {"enabled": False, "state": "disabled_future_extension"},
                "package_formats": {"ELF": "supported", "RPM": "future", "DEB": "future", "APK": "future"},
                "sample_count": len(SAMPLES),
                "upload_limit_bytes": MAX_FILE_BYTES,
            })
            return
        if path == "/api/samples":
            self._json({"samples": [public_sample(item) for item in SAMPLES]})
            return
        if path == "/api/apps":
            try:
                apps = [{**item, "source": "flatpak"} for item in list_flatpak_apps()]
            except (RuntimeError, ValueError) as exc:
                # No Flatpak (Windows, or Linux without flatpak) is a normal
                # state, not a server failure: return an empty list + reason.
                self._json({"apps": [], "available": False, "warnings": [str(exc)]})
                return
            self._json({"apps": apps, "available": True})
            return
        target_suffix = "/targets"
        app_prefix = "/api/apps/"
        if path.startswith(app_prefix) and path.endswith(target_suffix):
            app_id = path[len(app_prefix):-len(target_suffix)].strip("/")
            try:
                discovered = discover_flatpak_targets(app_id)
            except ValueError as exc:
                self._json({"error": str(exc)}, 404)
                return
            except RuntimeError as exc:
                self._json({"error": str(exc)}, 503)
                return
            safe_targets = [
                {key: value for key, value in target.items() if key != "absolute_path"}
                for target in discovered["targets"]
            ]
            self._json({
                "app": discovered["app"],
                "targets": safe_targets,
                "runtime": discovered["runtime"],
            })
            return
        self._json({"error": "Route not found."}, 404)

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        sample_prefix = "/api/analyze/sample/"
        if path.startswith(sample_prefix):
            self._analyze_sample(path[len(sample_prefix):])
            return
        if path == "/api/analyze/upload":
            self._analyze_upload(urlsplit(self.path).query)
            return
        self._json({"error": "Route not found."}, 404)

    def _requested_detail(self) -> str:
        try:
            body = self._read_body(4096)
            payload = json.loads(body.decode("utf-8")) if body else {}
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return "summary"
        return "full" if isinstance(payload, dict) and payload.get("detail") == "full" else "summary"

    def _analyze_sample(self, sample_id: str) -> None:
        detail = self._requested_detail()
        sample = get_sample(sample_id)
        if sample is None:
            self._json({"error": "Unknown sample id."}, 404)
            return
        binary = (ROOT / sample["binary"]).resolve()
        if not binary.is_relative_to(SAMPLE_ROOT.resolve()) or not binary.is_file():
            self._json({"error": "Sample binaries are not built. Run build_samples.py first."}, 409)
            return
        try:
            result = analyze_elf(binary, filename=sample["name"], detail=detail)
        except (OSError, ValueError) as exc:
            self._json({"error": str(exc)}, 400)
            return
        result["sample"] = {"id": sample["id"], "complexity": sample["complexity"], "description": sample["description"]}
        self._json(result)

    def _analyze_upload(self, query: str) -> None:
        params = parse_qs(query, keep_blank_values=True)
        user_name = params.get("filename", ["uploaded.elf"])[0].replace("\\", "/")
        display_name = Path(user_name).name[:120] or "uploaded.elf"
        detail = "full" if params.get("detail", ["summary"])[0] == "full" else "summary"
        try:
            data = self._read_body(MAX_FILE_BYTES)
        except ValueError as exc:
            self._json({"error": str(exc)}, 413)
            return
        if not has_elf_magic(data[:4]):
            self._json({"error": "Unsupported input. Choose a Linux ELF executable; RPM, DEB and APK are not enabled in this milestone."}, 415)
            return
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(prefix="reverseshield-", suffix=".elf", delete=False) as stream:
                temp_path = stream.name
                stream.write(data)
            result = analyze_elf(temp_path, filename=display_name, detail=detail)
            result["storage"] = "temporary file removed after analysis"
            self._json(result)
        except (OSError, ValueError) as exc:
            self._json({"error": str(exc)}, 400)
        finally:
            if temp_path:
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass

    def do_OPTIONS(self) -> None:
        self._json({"error": "Cross-origin requests are not enabled."}, 405)


from http_upgrade import UpgradeApiMixin


class ReverseShieldHandler(UpgradeApiMixin, LegacyMetadataHandler):
    """Upgraded routes plus the original metadata endpoints."""


class WorkbenchServer(ThreadingHTTPServer):
    daemon_threads = True

    def server_close(self):
        super().server_close()
        if hasattr(self, 'workbench'):
            self.workbench.close()


def create_server() -> ThreadingHTTPServer:
    for port in range(PORT_START, PORT_START + 10):
        try:
            return WorkbenchServer(("127.0.0.1", port), ReverseShieldHandler)
        except OSError:
            continue
    raise OSError("No available local port between 8765 and 8774.")


def main() -> None:
    server = create_server()
    host, port = server.server_address
    print(f"ReverseShield Workbench v0.5.0-team listening on http://{host}:{port}", flush=True)
    print("Static ELF/PE analysis only. The server does not execute selected binaries.")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping ReverseShield Local Demo.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
