"""Push notifications (Telegram / Discord) — fail-soft by design."""

from __future__ import annotations

from loguru import logger

try:
    import requests

    _HAS_REQUESTS = True
except ImportError:  # pragma: no cover
    _HAS_REQUESTS = False


def send_telegram(token: str, chat_id: str, text: str) -> bool:
    if not (_HAS_REQUESTS and token and chat_id):
        return False
    try:
        resp = requests.get(
            f"https://api.telegram.org/bot{token}/sendMessage",
            params={"chat_id": chat_id, "text": text[:4000]},
            timeout=10,
        )
        return resp.status_code == 200
    except Exception as exc:
        logger.debug("telegram notify failed: {}", exc)
        return False


def send_discord(webhook: str, text: str) -> bool:
    if not (_HAS_REQUESTS and webhook):
        return False
    try:
        resp = requests.post(webhook, json={"content": f"```{text[:1900]}```"}, timeout=10)
        return resp.status_code in (200, 204)
    except Exception as exc:
        logger.debug("discord notify failed: {}", exc)
        return False


def make_notifier(settings):
    """Return a callable(text) that fans out to every configured channel."""

    def notify(text: str) -> None:
        if (
            settings.telegram_token
            and settings.telegram_chat_id
            and send_telegram(settings.telegram_token, settings.telegram_chat_id, text)
        ):
            logger.info("Telegram notification sent")
        if settings.discord_webhook and send_discord(settings.discord_webhook, text):
            logger.info("Discord notification sent")

    return notify
