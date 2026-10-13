"""Find the Telegram chat id for notifications.

The bot token is part of the request URL, so it must never reach output or error messages:
every error here is rebuilt from safe parts (status code, Telegram's description).
"""

from __future__ import annotations

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError

from accessops.errors import AccessOpsError

API_URL = "https://api.telegram.org"


class TelegramError(AccessOpsError):
    """Telegram API call failed (the message never contains the token)."""


class _Model(BaseModel):
    # Telegram adds new fields over time: ignore unknown ones, validate what we use.
    model_config = ConfigDict(extra="ignore", frozen=True)


class Chat(_Model):
    id: int
    type: str
    first_name: str | None = None
    username: str | None = None

    @property
    def label(self) -> str:
        return self.first_name or self.username or "unknown"


class Message(_Model):
    chat: Chat


class Update(_Model):
    update_id: int
    message: Message | None = None
    edited_message: Message | None = None


class UpdatesResponse(_Model):
    ok: bool
    description: str | None = None
    result: list[Update] = []


def private_chats(updates: list[Update]) -> list[Chat]:
    """Distinct private chats (people who wrote to the bot), in order of appearance."""
    chats: dict[int, Chat] = {}
    for update in updates:
        message = update.message or update.edited_message
        if message is not None and message.chat.type == "private":
            chats.setdefault(message.chat.id, message.chat)
    return list(chats.values())


def parse_updates(payload: object) -> list[Update]:
    try:
        response = UpdatesResponse.model_validate(payload)
    except ValidationError:
        raise TelegramError("Telegram returned an unexpected getUpdates response.") from None
    if not response.ok:
        raise TelegramError(f"Telegram refused getUpdates: {response.description or 'no reason'}")
    return response.result


def fetch_updates(token: str, *, client: httpx.Client | None = None) -> list[Update]:
    http = client or httpx.Client(timeout=15)
    try:
        response = http.get(f"{API_URL}/bot{token}/getUpdates")
        payload = response.json()
    except httpx.HTTPError as exc:
        raise TelegramError(f"Cannot reach Telegram: {type(exc).__name__}.") from None
    except ValueError:
        raise TelegramError(f"Telegram answered HTTP {response.status_code}, not JSON.") from None
    finally:
        if client is None:
            http.close()
    return parse_updates(payload)
