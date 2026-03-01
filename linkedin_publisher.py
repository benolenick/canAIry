#!/usr/bin/env python3
"""
linkedin_publisher.py — Auto-publish benjaminolenick.com blog posts to LinkedIn.

Usage:
    python linkedin_publisher.py setup
    python linkedin_publisher.py publish <file.html>
    python linkedin_publisher.py auto
"""

import argparse
import http.server
import json
import os
import re
import sys
import threading
import time
import urllib.parse
import urllib.request
import webbrowser
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

import requests

try:
    import paramiko
except ImportError:
    print("ERROR: paramiko is required. Install with: pip install paramiko")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants / paths
# ---------------------------------------------------------------------------

CONFIG_DIR = Path.home() / ".canairy"
CONFIG_FILE = CONFIG_DIR / "linkedin_config.json"
PUBLISHED_FILE = CONFIG_DIR / "linkedin_published.json"

OAUTH_PORT = 8585
REDIRECT_URI = f"http://localhost:{OAUTH_PORT}/callback"
AUTH_URL = "https://www.linkedin.com/oauth/v2/authorization"
TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"
USERINFO_URL = "https://api.linkedin.com/v2/userinfo"
POSTS_URL = "https://api.linkedin.com/rest/posts"
LINKEDIN_API_VERSION = "202602"

SFTP_HOST = "ontariogreenlife.org"
SFTP_PORT = 2222
SFTP_USER = "benolenick"
SFTP_BLOG_DIR = "/home1/benolenick/benjaminolenick.com/blog/"

DEFAULT_BLOG_BASE_URL = "https://benjaminolenick.com/blog/"


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def load_config() -> dict:
    """Load config from disk, returning empty dict if missing."""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_config(cfg: dict) -> None:
    """Persist config to disk (creates directory if needed)."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    print(f"Config saved to {CONFIG_FILE}")


def load_published() -> dict:
    """Load the set of already-published posts."""
    if PUBLISHED_FILE.exists():
        with open(PUBLISHED_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_published(published: dict) -> None:
    """Persist the published-posts record."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(PUBLISHED_FILE, "w", encoding="utf-8") as f:
        json.dump(published, f, indent=2)


def require_config() -> dict:
    """Load config or exit with a helpful message."""
    cfg = load_config()
    required = ["access_token", "person_id", "client_id", "client_secret"]
    missing = [k for k in required if not cfg.get(k)]
    if missing:
        print(f"ERROR: Config missing keys: {', '.join(missing)}")
        print("Run `python linkedin_publisher.py setup` first.")
        sys.exit(1)
    return cfg


# ---------------------------------------------------------------------------
# OAuth 2.0 — three-legged flow
# ---------------------------------------------------------------------------

_oauth_code: str | None = None
_oauth_error: str | None = None


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    """Minimal HTTP handler that captures the OAuth callback code."""

    def do_GET(self):  # noqa: N802
        global _oauth_code, _oauth_error
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if "code" in params:
            _oauth_code = params["code"][0]
            body = b"<h2>Authorization successful! You can close this tab.</h2>"
        elif "error" in params:
            _oauth_error = params.get("error_description", ["Unknown error"])[0]
            body = (
                f"<h2>Authorization failed: {_oauth_error}</h2>".encode()
            )
        else:
            body = b"<h2>Unexpected callback. Check the terminal.</h2>"

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # suppress default access log noise
        pass


def run_oauth_flow(client_id: str, client_secret: str) -> tuple[str, str, int]:
    """
    Run the full 3-legged OAuth flow.

    Returns (access_token, person_id, expires_in_seconds).
    """
    global _oauth_code, _oauth_error
    _oauth_code = None
    _oauth_error = None

    # Start local callback server
    server = http.server.HTTPServer(("localhost", OAUTH_PORT), _CallbackHandler)
    server.timeout = 1

    params = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid profile w_member_social",
        }
    )
    auth_url = f"{AUTH_URL}?{params}"

    print(f"\nOpening browser for LinkedIn authorization...")
    print(f"If the browser does not open, visit:\n  {auth_url}\n")
    webbrowser.open(auth_url)

    # Poll until we get the code (timeout: 120 s)
    deadline = time.time() + 120
    while time.time() < deadline:
        server.handle_request()
        if _oauth_code or _oauth_error:
            break

    server.server_close()

    if _oauth_error:
        print(f"ERROR: OAuth failed — {_oauth_error}")
        sys.exit(1)
    if not _oauth_code:
        print("ERROR: Timed out waiting for OAuth callback.")
        sys.exit(1)

    print("Authorization code received. Exchanging for access token...")

    # Exchange code for token
    resp = requests.post(
        TOKEN_URL,
        data={
            "grant_type": "authorization_code",
            "code": _oauth_code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": REDIRECT_URI,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
    )
    resp.raise_for_status()
    token_data = resp.json()

    access_token = token_data.get("access_token")
    expires_in = token_data.get("expires_in", 0)

    if not access_token:
        print(f"ERROR: No access_token in response: {token_data}")
        sys.exit(1)

    print("Access token obtained. Fetching LinkedIn profile...")

    # Get person URN
    profile_resp = requests.get(
        USERINFO_URL,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=30,
    )
    profile_resp.raise_for_status()
    profile = profile_resp.json()
    person_id = profile.get("sub")

    if not person_id:
        print(f"ERROR: Could not determine person ID from profile: {profile}")
        sys.exit(1)

    print(f"Authenticated as: {profile.get('name', person_id)}")
    return access_token, person_id, expires_in


# ---------------------------------------------------------------------------
# HTML parsing
# ---------------------------------------------------------------------------

class BlogPostParser(HTMLParser):
    """
    Extracts structured data from a benjaminolenick.com blog post HTML file.

    Collects:
    - title          (h1.post-title)
    - subtitle       (p.post-subtitle)
    - tags           (span.tag inside .post-meta)
    - date           (time inside .post-meta)
    - first_paragraph (first <p> inside .post-content)
    """

    def __init__(self):
        super().__init__()
        self.title: str = ""
        self.subtitle: str = ""
        self.tags: list[str] = []
        self.date: str = ""
        self.first_paragraph: str = ""

        self._in_post_meta = False
        self._in_post_content = False
        self._in_h1_post_title = False
        self._in_p_post_subtitle = False
        self._in_tag_span = False
        self._in_time = False
        self._in_first_p = False
        self._first_p_done = False
        self._meta_depth = 0
        self._content_depth = 0
        self._current_depth = 0

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _has_class(attrs: list, *classes: str) -> bool:
        attr_dict = dict(attrs)
        elem_classes = attr_dict.get("class", "").split()
        return any(c in elem_classes for c in classes)

    # -- handlers ------------------------------------------------------------

    def handle_starttag(self, tag, attrs):
        self._current_depth += 1
        attr_dict = dict(attrs)
        classes = attr_dict.get("class", "").split()

        # --- .post-meta container ---
        if tag == "div" and "post-meta" in classes:
            self._in_post_meta = True
            self._meta_depth = self._current_depth
            return

        # --- .post-content container ---
        if tag == "div" and "post-content" in classes:
            self._in_post_content = True
            self._content_depth = self._current_depth
            return

        # --- h1.post-title ---
        if tag == "h1" and "post-title" in classes:
            self._in_h1_post_title = True
            return

        # --- p.post-subtitle ---
        if tag == "p" and "post-subtitle" in classes:
            self._in_p_post_subtitle = True
            return

        # --- span.tag inside .post-meta ---
        if self._in_post_meta and tag == "span":
            if any(c.startswith("tag") for c in classes):
                self._in_tag_span = True
            return

        # --- time inside .post-meta ---
        if self._in_post_meta and tag == "time":
            self._in_time = True
            # Also capture datetime attribute if present
            if "datetime" in attr_dict and not self.date:
                self.date = attr_dict["datetime"]
            return

        # --- first <p> inside .post-content ---
        if (
            self._in_post_content
            and tag == "p"
            and not self._first_p_done
            and not self._in_first_p
        ):
            self._in_first_p = True
            return

    def handle_endtag(self, tag):
        if self._in_post_meta and self._current_depth == self._meta_depth:
            self._in_post_meta = False

        if self._in_post_content and self._current_depth == self._content_depth:
            self._in_post_content = False

        if tag == "h1" and self._in_h1_post_title:
            self._in_h1_post_title = False

        if tag == "p" and self._in_p_post_subtitle:
            self._in_p_post_subtitle = False

        if tag == "span" and self._in_tag_span:
            self._in_tag_span = False

        if tag == "time" and self._in_time:
            self._in_time = False

        if tag == "p" and self._in_first_p:
            self._in_first_p = False
            self._first_p_done = True

        self._current_depth -= 1

    def handle_data(self, data):
        text = data.strip()
        if not text:
            return

        if self._in_h1_post_title and not self.title:
            self.title += text
        elif self._in_p_post_subtitle and not self.subtitle:
            self.subtitle += text
        elif self._in_tag_span:
            self.tags.append(text.strip().lstrip("#"))
        elif self._in_time and not self.date:
            self.date = text
        elif self._in_first_p and not self._first_p_done:
            self.first_paragraph += text


def parse_blog_post(html_content: str) -> dict:
    """Parse HTML and return a dict with post metadata."""
    parser = BlogPostParser()
    parser.feed(html_content)
    return {
        "title": parser.title or "Untitled",
        "subtitle": parser.subtitle or "",
        "tags": parser.tags,
        "date": parser.date,
        "first_paragraph": parser.first_paragraph,
    }


def build_hashtags(tags: list[str]) -> str:
    """Convert a list of tag strings into hashtag string."""
    # Normalize: strip spaces, camelCase multi-word tags
    hashtags = []
    for tag in tags:
        cleaned = re.sub(r"[^\w\s]", "", tag)
        words = cleaned.split()
        if len(words) > 1:
            ht = words[0].lower() + "".join(w.capitalize() for w in words[1:])
        else:
            ht = words[0].lower() if words else ""
        if ht:
            hashtags.append(f"#{ht}")
    return " ".join(hashtags)


# ---------------------------------------------------------------------------
# SFTP helpers
# ---------------------------------------------------------------------------

def _make_sftp_client(cfg: dict) -> tuple[paramiko.SSHClient, paramiko.SFTPClient]:
    """Create and return (ssh_client, sftp_client) using config."""
    key_path = cfg.get("ssh_key_path", "")
    key_password = cfg.get("ssh_key_password", None) or None

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs: dict = {
        "hostname": SFTP_HOST,
        "port": SFTP_PORT,
        "username": SFTP_USER,
        "allow_agent": False,
        "look_for_keys": False,
        "timeout": 30,
    }

    if key_path and Path(key_path).exists():
        try:
            pkey = paramiko.RSAKey.from_private_key_file(key_path, password=key_password)
            connect_kwargs["pkey"] = pkey
        except paramiko.ssh_exception.SSHException:
            try:
                pkey = paramiko.Ed25519Key.from_private_key_file(key_path, password=key_password)
                connect_kwargs["pkey"] = pkey
            except Exception as e:
                print(f"WARNING: Could not load SSH key ({e}), will try password auth.")
                if key_password:
                    connect_kwargs["password"] = key_password
    elif key_password:
        connect_kwargs["password"] = key_password

    ssh.connect(**connect_kwargs)
    sftp = ssh.open_sftp()
    return ssh, sftp


def list_blog_html_files(cfg: dict) -> list[str]:
    """Return list of HTML filenames in the remote blog directory."""
    ssh, sftp = _make_sftp_client(cfg)
    try:
        entries = sftp.listdir(SFTP_BLOG_DIR)
        return [e for e in entries if e.endswith(".html") and e != "index.html"]
    finally:
        sftp.close()
        ssh.close()


def read_remote_html(cfg: dict, filename: str) -> str:
    """Read a single HTML file from the remote blog directory via SFTP."""
    ssh, sftp = _make_sftp_client(cfg)
    try:
        remote_path = SFTP_BLOG_DIR + filename
        with sftp.open(remote_path, "r") as f:
            return f.read().decode("utf-8", errors="replace")
    finally:
        sftp.close()
        ssh.close()


# ---------------------------------------------------------------------------
# LinkedIn posting
# ---------------------------------------------------------------------------

def post_to_linkedin(cfg: dict, post_data: dict, filename: str) -> str:
    """
    Publish a blog post to LinkedIn.

    Returns the LinkedIn post URN on success.
    """
    token = cfg["access_token"]
    person_id = cfg["person_id"]
    blog_base_url = cfg.get("blog_base_url", DEFAULT_BLOG_BASE_URL).rstrip("/") + "/"

    title = post_data["title"]
    subtitle = post_data.get("subtitle", "")
    tags = post_data.get("tags", [])
    first_paragraph = post_data.get("first_paragraph", "")

    # Build URL — strip .html and use clean slug, or keep as-is
    slug = filename[:-5] if filename.endswith(".html") else filename
    post_url = blog_base_url + filename

    # Build hashtags: use post tags, then fall back to defaults
    if tags:
        hashtag_str = build_hashtags(tags)
    else:
        hashtag_str = "#cybersecurity #honeypot #AI #LLM #infosec"

    # Commentary (the visible post text)
    excerpt = first_paragraph[:300] if first_paragraph else subtitle[:300]
    commentary = (
        f"NEW BLOG POST: {title}\n\n"
        f"{excerpt}\n\n"
        f"Read the full post: {post_url}\n\n"
        f"{hashtag_str}"
    )

    payload = {
        "author": f"urn:li:person:{person_id}",
        "commentary": commentary,
        "visibility": "PUBLIC",
        "distribution": {
            "feedDistribution": "MAIN_FEED",
            "targetEntities": [],
            "thirdPartyDistributionChannels": [],
        },
        "content": {
            "article": {
                "source": post_url,
                "title": title,
                "description": subtitle or excerpt,
            }
        },
        "lifecycleState": "PUBLISHED",
        "isReshareDisabledByAuthor": False,
    }

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-Restli-Protocol-Version": "2.0.0",
        "Linkedin-Version": LINKEDIN_API_VERSION,
    }

    resp = requests.post(POSTS_URL, headers=headers, json=payload, timeout=30)

    if resp.status_code == 201:
        post_urn = resp.headers.get("x-restli-id", "")
        print(f"  Posted successfully. URN: {post_urn}")
        return post_urn
    else:
        print(f"  ERROR: LinkedIn API returned {resp.status_code}")
        print(f"  Response: {resp.text[:500]}")
        resp.raise_for_status()


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_setup(args):
    """Interactive setup: collect credentials and run OAuth flow."""
    print("=== LinkedIn Publisher Setup ===\n")

    existing = load_config()

    client_id = input(
        f"LinkedIn Client ID [{existing.get('client_id', '')}]: "
    ).strip() or existing.get("client_id", "")
    client_secret = input(
        f"LinkedIn Client Secret [{existing.get('client_secret', '')}]: "
    ).strip() or existing.get("client_secret", "")

    if not client_id or not client_secret:
        print("ERROR: Client ID and Client Secret are required.")
        sys.exit(1)

    # SSH / SFTP details
    default_key = existing.get("ssh_key_path", str(Path.home() / ".ssh" / "id_rsa"))
    ssh_key_path = input(f"SSH key path [{default_key}]: ").strip() or default_key

    ssh_key_password = input("SSH key password (leave blank if none): ").strip() or ""

    default_blog_url = existing.get("blog_base_url", DEFAULT_BLOG_BASE_URL)
    blog_base_url = (
        input(f"Blog base URL [{default_blog_url}]: ").strip() or default_blog_url
    )

    # Run OAuth
    access_token, person_id, expires_in = run_oauth_flow(client_id, client_secret)

    expires_at = None
    if expires_in:
        expires_at = datetime.fromtimestamp(
            time.time() + expires_in, tz=timezone.utc
        ).isoformat()

    cfg = {
        "client_id": client_id,
        "client_secret": client_secret,
        "access_token": access_token,
        "person_id": person_id,
        "expires_at": expires_at,
        "ssh_key_path": ssh_key_path,
        "ssh_key_password": ssh_key_password,
        "blog_base_url": blog_base_url.rstrip("/") + "/",
    }

    save_config(cfg)

    print("\nSetup complete!")
    if expires_at:
        print(f"Token expires at: {expires_at}")
    print("You can now run: python linkedin_publisher.py auto")


def cmd_publish(args):
    """Publish a specific HTML file (by filename, read from SFTP)."""
    filename: str = args.file
    if not filename.endswith(".html"):
        filename += ".html"

    print(f"=== Publishing: {filename} ===")
    cfg = require_config()
    published = load_published()

    if filename in published:
        print(f"Already published on {published[filename].get('published_at', '?')}.")
        print("Use --force to publish again (not currently implemented).")
        return

    print(f"Fetching {filename} from {SFTP_HOST}...")
    try:
        html = read_remote_html(cfg, filename)
    except Exception as e:
        print(f"ERROR fetching file via SFTP: {e}")
        sys.exit(1)

    post_data = parse_blog_post(html)
    print(f"  Title    : {post_data['title']}")
    print(f"  Subtitle : {post_data['subtitle']}")
    print(f"  Tags     : {', '.join(post_data['tags'])}")
    print(f"  Date     : {post_data['date']}")

    print("Posting to LinkedIn...")
    try:
        post_urn = post_to_linkedin(cfg, post_data, filename)
    except Exception as e:
        print(f"ERROR posting to LinkedIn: {e}")
        sys.exit(1)

    published[filename] = {
        "published_at": datetime.now(tz=timezone.utc).isoformat(),
        "linkedin_post_id": post_urn,
        "title": post_data["title"],
    }
    save_published(published)
    print(f"Done. Recorded in {PUBLISHED_FILE}")


def cmd_auto(args):
    """Scan remote blog directory and publish all unpublished posts."""
    print("=== Auto-publish mode ===")
    cfg = require_config()
    published = load_published()

    print(f"Connecting to {SFTP_HOST}:{SFTP_PORT} to list blog posts...")
    try:
        all_files = list_blog_html_files(cfg)
    except Exception as e:
        print(f"ERROR listing blog files via SFTP: {e}")
        sys.exit(1)

    print(f"Found {len(all_files)} HTML file(s) in blog directory.")

    to_publish = [f for f in all_files if f not in published]
    skipped = len(all_files) - len(to_publish)

    if skipped:
        print(f"Skipping {skipped} already-published file(s).")

    if not to_publish:
        print("Nothing new to publish.")
        return

    print(f"Will publish {len(to_publish)} new post(s).\n")

    results = {"published": 0, "failed": 0}

    for filename in to_publish:
        print(f"--- {filename} ---")
        try:
            html = read_remote_html(cfg, filename)
        except Exception as e:
            print(f"  ERROR fetching {filename}: {e}")
            results["failed"] += 1
            continue

        post_data = parse_blog_post(html)
        print(f"  Title: {post_data['title']}")

        try:
            post_urn = post_to_linkedin(cfg, post_data, filename)
        except Exception as e:
            print(f"  ERROR posting {filename}: {e}")
            results["failed"] += 1
            continue

        published[filename] = {
            "published_at": datetime.now(tz=timezone.utc).isoformat(),
            "linkedin_post_id": post_urn,
            "title": post_data["title"],
        }
        save_published(published)
        results["published"] += 1

        # Be polite to the API — wait between posts
        if filename != to_publish[-1]:
            print("  Waiting 3s before next post...")
            time.sleep(3)

    print(f"\nDone. Published: {results['published']}, Failed: {results['failed']}")
    print(f"Published log: {PUBLISHED_FILE}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Publish benjaminolenick.com blog posts to LinkedIn.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python linkedin_publisher.py setup
  python linkedin_publisher.py publish canairy-llm-honeypot.html
  python linkedin_publisher.py auto
""",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # setup
    subparsers.add_parser("setup", help="One-time OAuth setup")

    # publish
    pub_parser = subparsers.add_parser("publish", help="Publish a specific post")
    pub_parser.add_argument("file", help="HTML filename (e.g. canairy-llm-honeypot.html)")

    # auto
    subparsers.add_parser("auto", help="Publish all unpublished posts")

    args = parser.parse_args()

    if args.command == "setup":
        cmd_setup(args)
    elif args.command == "publish":
        cmd_publish(args)
    elif args.command == "auto":
        cmd_auto(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
