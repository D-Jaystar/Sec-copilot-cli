"""
sec-copilot-cli.src.client
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Gemini API wrapper with custom SafetySettings tuned for defensive
security analysis.

Architecture Decision:
    Safety thresholds are set to BLOCK_NONE for harm categories that
    commonly produce false-positive blocks during legitimate vulnerability
    discussions (e.g. HARM_CATEGORY_DANGEROUS_CONTENT).  This ensures
    authorized defensive audits are never interrupted by over-eager filters.
    The wrapper exposes a thin interface so callers never touch raw SDK
    objects directly.
"""

from __future__ import annotations

import os
import sys
from typing import Optional

from dotenv import load_dotenv
from google import genai
from google.genai import types

from src.prompts import get_system_prompt


# ──────────────────────────────────────────────────────────────
# Safety configuration — tuned for defensive security auditing
# ──────────────────────────────────────────────────────────────

# These thresholds prevent the API from blocking legitimate
# vulnerability descriptions, exploit-pattern explanations, and
# log-analysis responses that reference attack techniques.
SAFETY_SETTINGS: list[types.SafetySetting] = [
    types.SafetySetting(
        category="HARM_CATEGORY_HARASSMENT",
        threshold="BLOCK_ONLY_HIGH",
    ),
    types.SafetySetting(
        category="HARM_CATEGORY_HATE_SPEECH",
        threshold="BLOCK_ONLY_HIGH",
    ),
    types.SafetySetting(
        category="HARM_CATEGORY_SEXUALLY_EXPLICIT",
        threshold="BLOCK_ONLY_HIGH",
    ),
    types.SafetySetting(
        category="HARM_CATEGORY_DANGEROUS_CONTENT",
        threshold="BLOCK_NONE",          # critical for security analysis
    ),
]

# Default Gemini model — can be overridden via environment variable.
DEFAULT_MODEL: str = "gemini-2.5-flash"


# ──────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────

class GeminiClient:
    """Thin wrapper around the Google GenAI SDK.

    Responsibilities:
        - Load the API key from the environment.
        - Apply the security-tuned SafetySettings on every request.
        - Expose a simple ``generate`` method for higher layers.
    """

    def __init__(self, model: Optional[str] = None) -> None:
        """Initialise the Gemini client.

        Args:
            model: Model identifier to use.  Falls back to the
                   ``GEMINI_MODEL`` env var, then ``DEFAULT_MODEL``.

        Raises:
            SystemExit: If ``GEMINI_API_KEY`` is not set.
        """
        # --- Guard: API key must be present ---
        load_dotenv()
        self._api_key: str | None = os.getenv("GEMINI_API_KEY")

        if not self._api_key or self._api_key == "your-api-key-here":
            print(
                "[!] GEMINI_API_KEY is not configured.\n"
                "    Copy .env.example → .env and set your key.",
                file=sys.stderr,
            )
            sys.exit(1)

        # --- Resolve model name ---
        self._model_name: str = (
            model
            or os.getenv("GEMINI_MODEL")
            or DEFAULT_MODEL
        )

        # --- Instantiate SDK client ---
        self._client = genai.Client(api_key=self._api_key)

    # ----------------------------------------------------------
    # Core generation method
    # ----------------------------------------------------------

    def generate(
        self,
        user_content: str,
        mode: str = "audit",
        *,
        temperature: float = 0.3,
    ) -> str:
        """Send a single user prompt to Gemini and return the response text.

        Args:
            user_content:  The user's input (code snippet, log, question).
            mode:          Prompt mode key — determines which system
                           instruction is loaded from prompts.py.
            temperature:   Sampling temperature.  Lower values produce
                           more deterministic, audit-friendly output.

        Returns:
            The model's text response.

        Raises:
            ValueError:  If *mode* is unknown (propagated from prompts.py).
            RuntimeError: If the API response is empty or blocked.
        """
        # Guard clause — empty input
        if not user_content or not user_content.strip():
            raise ValueError("user_content must not be empty.")

        system_instruction = get_system_prompt(mode)

        response = self._client.models.generate_content(
            model=self._model_name,
            contents=user_content,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                safety_settings=SAFETY_SETTINGS,
                temperature=temperature,
            ),
        )

        # Guard clause — blocked or empty response
        if not response.text:
            raise RuntimeError(
                "Gemini returned an empty response.  "
                "The request may have been blocked by safety filters."
            )

        return response.text

    # ----------------------------------------------------------
    # Stateful Chat methods (Conversation Memory)
    # ----------------------------------------------------------

    def start_chat(self, mode: str = "chat", temperature: float = 0.3) -> None:
        """Initialise a multi-turn, stateful chat session.

        Args:
            mode: Prompt mode key for the system persona (default: chat).
            temperature: Sampling temperature.
        """
        system_instruction = get_system_prompt(mode)

        self._chat_session = self._client.chats.create(
            model=self._model_name,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                safety_settings=SAFETY_SETTINGS,
                temperature=temperature,
            )
        )

    def send_chat_message(self, message: str) -> str:
        """Send a message within the active stateful session.

        Raises:
            RuntimeError: If called before start_chat() or if response is blocked.
        """
        # Guard clause — ensure the Instance exists
        if not hasattr(self, '_chat_session') or not self._chat_session:
            raise RuntimeError("Chat session not initialized. Call start_chat() first.")

        # Guard clause — empty input
        if not message or not message.strip():
            raise ValueError("Message must not be empty.")

        response = self._chat_session.send_message(message)

        # Guard clause — blocked or empty response
        if not response.text:
            raise RuntimeError(
                "Gemini returned an empty response in chat. "
                "The request may have been blocked by safety filters."
            )

        return response.text