"""Display helper functions for safe output formatting."""

def escape_for_display(text: str, max_length: int = 100) -> str:
    """Escape special characters for clean table display.

    Args:
        text: Text to escape
        max_length: Maximum length before truncation

    Returns:
        Safe-to-display string with control chars escaped
    """
    if not text:
        return "(empty)"

    # Convert to string if not already
    text = str(text)

    # Replace control characters with visible escapes
    text = text.replace('\n', '\\n')
    text = text.replace('\r', '\\r')
    text = text.replace('\t', '\\t')

    return text