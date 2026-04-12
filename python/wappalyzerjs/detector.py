"""Core detection API — loads the JS bundle and evaluates it in a Playwright page."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from playwright.async_api import Page

_BUNDLE_PATH = Path(__file__).parent / 'bundle' / 'detect-full.bundle.js'
_bundle_cache: str | None = None


def get_detection_script() -> str:
    """Return the wappalyzerjs detection script as a string.

    The returned string can be passed to ``page.evaluate()`` followed by
    ``wappalyzerjs.detect()`` to run detection in the browser context.
    """
    global _bundle_cache
    if _bundle_cache is None:
        _bundle_cache = _BUNDLE_PATH.read_text(encoding='utf-8')
    return _bundle_cache


async def detect(page: Page) -> list[dict[str, Any]]:
    """Run technology detection on a Playwright page.

    Args:
        page: A Playwright page that has already navigated to the target URL.

    Returns:
        List of detected technologies, each with keys:
        name, version, confidence, categories, categoryNames,
        website, cpe, evidence.
    """
    script = get_detection_script()
    results: list[dict[str, Any]] = await page.evaluate(script + '\n; wappalyzerjs.detect();')
    return results
