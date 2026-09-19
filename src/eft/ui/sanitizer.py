"""HTML & Plaintext Body Sanitization Engine for Forensic Sandboxed Email Previews."""

from __future__ import annotations

import html
import re
from typing import List, Optional


class HTMLSanitizer:
    """Hardened sanitizer that strips active content, blocks tracking pixels, and defangs URLs."""

    # Dangerous tags to remove completely including content
    DANGEROUS_TAGS_WITH_CONTENT: List[str] = [
        "script",
        "style",
        "object",
        "embed",
        "applet",
        "iframe",
        "frame",
        "frameset",
        "form",
        "button",
        "textarea",
        "select",
        "option",
    ]

    # Dangerous self-closing / single tags to remove
    DANGEROUS_SINGLE_TAGS: List[str] = [
        "base",
        "meta",
        "link",
        "input",
    ]

    @classmethod
    def sanitize_html(
        cls,
        raw_html: Optional[str],
        block_remote_images: bool = True,
    ) -> str:
        """Sanitize raw HTML body to prevent any client-side code execution or network leakage.

        Args:
            raw_html: Unsanitized HTML string from email body.
            block_remote_images: If True, replaces remote HTTP/HTTPS images with blocked tracker badges.

        Returns:
            Sanitized, sandboxed HTML string ready for safe rendering.
        """
        if not raw_html:
            return "<div class='empty-body'><i>(No HTML content available)</i></div>"

        sanitized = raw_html

        # 1. Remove dangerous paired tags and their internal text
        for tag in cls.DANGEROUS_TAGS_WITH_CONTENT:
            pattern = rf"<{tag}\b[^>]*>.*?</{tag}>"
            sanitized = re.sub(pattern, "", sanitized, flags=re.IGNORECASE | re.DOTALL)
            # Handle unclosed tags
            unclosed_pattern = rf"<{tag}\b[^>]*>"
            sanitized = re.sub(unclosed_pattern, "", sanitized, flags=re.IGNORECASE)

        # 2. Remove dangerous single tags
        for tag in cls.DANGEROUS_SINGLE_TAGS:
            pattern = rf"<{tag}\b[^>]*\/?>"
            sanitized = re.sub(pattern, "", sanitized, flags=re.IGNORECASE)

        # 3. Strip all inline event handlers (onload, onclick, onerror, onmouseover, etc.)
        event_handler_pattern = r"\s+on[a-zA-Z]+\s*=\s*(?:'[^']*'|\"[^\"]*\"|[^\s>]+)"
        sanitized = re.sub(event_handler_pattern, "", sanitized, flags=re.IGNORECASE)

        # 4. Neutralize javascript:, vbscript:, and data:text/html URIs in href and src
        proto_pattern = (
            r"""(href|src)\s*=\s*(['"])\s*(javascript|vbscript|data:\s*text\/html):.*?\2"""
        )
        sanitized = re.sub(
            proto_pattern,
            r"""\1=\2#defanged-executable-uri\2""",
            sanitized,
            flags=re.IGNORECASE,
        )

        # 5. Remote image tracking pixel blocker
        if block_remote_images:

            def replace_img(match: re.Match[str]) -> str:
                full_tag = match.group(0)
                src_match = re.search(r"""src\s*=\s*(['"])(.*?)\1""", full_tag, flags=re.IGNORECASE)
                if not src_match:
                    return ""
                src_val = src_match.group(2).strip()

                # Preserve inline attachments (cid:...) or safe inline data images
                if src_val.startswith("cid:") or src_val.startswith("data:image/"):
                    return full_tag

                # Defang URL for display
                defanged_src = (
                    src_val.replace("http://", "hxxp://")
                    .replace("https://", "hxxps://")
                    .replace(".", "[.]")
                )
                return (
                    f'<span class="eft-blocked-image" title="External Remote Tracker Blocked: {defanged_src}">'
                    f"🛡️ [Remote Image Blocked: <code>{defanged_src[:45]}...</code>]</span>"
                )

            img_pattern = r"<img\b[^>]*\/?>"
            sanitized = re.sub(img_pattern, replace_img, sanitized, flags=re.IGNORECASE)

        # 6. Secure hyperlinks: add target="_blank", rel="noopener noreferrer", and defang preview
        def secure_link(match: re.Match[str]) -> str:
            full_tag = match.group(0)
            href_match = re.search(r"""href\s*=\s*(['"])(.*?)\1""", full_tag, flags=re.IGNORECASE)
            if not href_match:
                return full_tag
            href_val = href_match.group(2).strip()
            defanged = (
                href_val.replace("http://", "hxxp[://]")
                .replace("https://", "hxxps[://]")
                .replace(".", "[.]")
            )
            # Replace tag with secure attributes
            cleaned_tag = re.sub(
                r"""\s*target\s*=\s*['"][^'"]*['"]""", "", full_tag, flags=re.IGNORECASE
            )
            cleaned_tag = re.sub(
                r"""\s*rel\s*=\s*['"][^'"]*['"]""", "", cleaned_tag, flags=re.IGNORECASE
            )

            return (
                cleaned_tag[:-1]
                + f' target="_blank" rel="noopener noreferrer" data-defanged="{defanged}" title="Target: {defanged}">'
            )

        sanitized = re.sub(r"<a\b[^>]*>", secure_link, sanitized, flags=re.IGNORECASE)

        return sanitized

    @classmethod
    def sanitize_plain_text(cls, plain_text: Optional[str]) -> str:
        """Escape and format plaintext message body for safe HTML presentation.

        Args:
            plain_text: Raw plain text body string.

        Returns:
            HTML escaped string wrapped in pre/code structure.
        """
        if not plain_text:
            return "<div class='empty-body'><i>(No plaintext content available)</i></div>"

        escaped = html.escape(plain_text)
        return f"<pre class='eft-plaintext-body'>{escaped}</pre>"
