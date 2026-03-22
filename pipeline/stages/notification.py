"""Notification dispatcher for pipeline events.

Sends alerts to Discord and/or Slack webhooks when key events occur.
Rate-limited to avoid spam: at most one notification per event type per min_interval seconds.

Usage (from any pipeline stage):
    from .notification import notify
    notify("takeover_found", f"Takeover candidate: {subdomain}", program="visma-vdp")
"""

import logging
import time
import os

import requests

from ..core.config import get_config

log = logging.getLogger(__name__)

# In-memory rate limit tracker: event_type -> last_sent_timestamp
_last_sent: dict[str, float] = {}


def notify(event: str, message: str, program: str = None, url: str = None):
    """Send a notification if this event type is enabled and not rate-limited.

    Args:
        event:   Event type string — must match config.notifications.events list.
        message: Human-readable description of what happened.
        program: Program name for context (optional).
        url:     Relevant URL (optional).
    """
    cfg = get_config().get("notifications", {})
    enabled_events = cfg.get("events", [])
    min_interval = cfg.get("min_interval", 300)

    if event not in enabled_events:
        return

    now = time.time()
    last = _last_sent.get(event, 0)
    if now - last < min_interval:
        log.debug(f"[notify] Rate-limited event '{event}' (next in {int(min_interval - (now - last))}s)")
        return

    _last_sent[event] = now

    text = _format_message(event, message, program, url)

    discord_url = cfg.get("discord_webhook") or os.environ.get("DISCORD_WEBHOOK", "")
    slack_url = cfg.get("slack_webhook") or os.environ.get("SLACK_WEBHOOK", "")

    if discord_url:
        _send_discord(discord_url, text, event)
    if slack_url:
        _send_slack(slack_url, text)

    if not discord_url and not slack_url:
        log.debug(f"[notify] No webhook configured for event: {event}")


def _format_message(event: str, message: str, program: str, url: str) -> str:
    parts = [f"**[{event.upper()}]** {message}"]
    if program:
        parts.append(f"Program: `{program}`")
    if url:
        parts.append(f"URL: {url}")
    return "\n".join(parts)


def _send_discord(webhook_url: str, text: str, event: str):
    # Map event severity to Discord embed colour
    colours = {
        "takeover_found": 0xFF0000,    # Red
        "new_apex_domain": 0x00FF00,   # Green
        "new_http_service": 0x0099FF,  # Blue
        "scan_complete": 0xAAAAAA,     # Grey
    }
    payload = {
        "embeds": [{
            "description": text,
            "color": colours.get(event, 0x888888),
        }]
    }
    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        log.warning(f"[notify] Discord send failed: {e}")


def _send_slack(webhook_url: str, text: str):
    payload = {"text": text}
    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        log.warning(f"[notify] Slack send failed: {e}")
