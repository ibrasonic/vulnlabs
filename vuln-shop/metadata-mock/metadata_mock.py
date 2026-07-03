# metadata_mock.py — a DELIBERATELY FAKE AWS instance metadata service (IMDS)
# for the SSRF chapter. It serves the same paths as the real link-local
# 169.254.169.254 so that an SSRF against vuln-shop can retrieve *simulated*
# IAM credentials, reproducing the shape of the 2019 Capital One breach.
#
# Every secret below is fake and inert. This service is reachable ONLY from
# inside the lab's docker network (it is bound to the link-local metadata
# address, which is unrouteable from your host/browser) — exactly like the
# real thing. Stdlib only; no dependencies.
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os

ROLE = "shop-app-role"

# Fake, inert IAM credentials in the exact shape AWS IMDS returns.
CREDS = {
    "Code": "Success",
    "LastUpdated": "2026-07-03T12:00:00Z",
    "Type": "AWS-HMAC",
    "AccessKeyId": "ASIAV7EXAMPLE7SHOP01",
    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "Token": "IQoJb3JpZ2luX2VjEDEMO-FAKE-DO-NOT-USE-EXAMPLE-TOKEN==",
    "Expiration": "2026-07-03T18:00:00Z",
}


class Handler(BaseHTTPRequestHandler):
    def _send(self, body, code=200, ctype="text/plain"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Server", "EC2ws")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        p = self.path.split("?")[0].rstrip("/")
        routes = {
            "": "latest",
            "/latest": "meta-data\napi",
            "/latest/meta-data": "ami-id\nhostname\niam/\ninstance-id",
            "/latest/meta-data/iam": "info\nsecurity-credentials/",
            "/latest/meta-data/iam/security-credentials": ROLE,
            "/latest/meta-data/instance-id": "i-0123456789abcdef0",
            "/latest/meta-data/hostname": "ip-10-0-3-14.eu-west-1.compute.internal",
        }
        if p == "/latest/meta-data/iam/security-credentials/" + ROLE:
            return self._send(json.dumps(CREDS, indent=2))
        if p in routes:
            return self._send(routes[p])
        return self._send("not found\n", code=404)

    def do_PUT(self):
        # IMDSv2 token endpoint, so v2 flows also work in demos.
        if self.path.split("?")[0].rstrip("/") == "/latest/api/token":
            return self._send("AQAEDEMO-FAKE-IMDSV2-TOKEN==")
        return self._send("not found\n", code=404)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "80"))
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
