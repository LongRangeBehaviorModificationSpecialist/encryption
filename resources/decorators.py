#!/usr/bin/env python3

from datetime import datetime
import functools
import logging
from typing import Callable, Tuple


def handle_exceptions(
    ui_handler = None,
    log_level = logging.ERROR,
    raise_on_error: bool = False,
    silent: bool = False,
    get_time_func = None,
):
    """Reusable exception handler decorator with automatic UI fallback.

    Args:
        ui_handler: Injected UI handler, or None to auto-instantiate
            RichUIHandler.
        log_level: Logging level for error messages.
        raise_on_error: If True, re-raise exceptions after logging.
        silent: If True, suppress all output (useful for batch operations).
        get_time_func: Optional callable to supply to RichUIHandler for
            timestamps.

    Example usage:
        # Auto-create RichUIHandler
        @handle_exceptions()
        def process_data(self, data: str) -> Dict[str, Any]:
            ...

        # Inject existing UI
        @handle_exceptions(ui_handler=self.ui, raise_on_error=True)
        def validate_input(self, data: str) -> bool:
            ...
    """

    def _get_ui_handler():
        """Lazy-load UI handler on first use."""
        if ui_handler is not None:
            return ui_handler

        # Auto-instantiate RichUIHandler if none provided
        try:
            from utils import RichUIHandler

            get_time = get_time_func or (
                lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
            return RichUIHandler(get_time=get_time)
        except ImportError:
            return None  # Fall back to silent mode


    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            func_name = func.__name__
            module_name = (
                func.__module__ if hasattr(func, "__module__") else "unknown"
            )

            # Get UI handler (lazy-loaded if not provided)
            ui = _get_ui_handler()

            try:
                return func(*args, **kwargs)

            except (
                AttributeError,
                TypeError,
                ValueError,
                UnicodeDecodeError,
            ) as err:
                # Extract context for error message
                context = _extract_context(args, func_name)

                error_msg = _format_error_message(
                    error_type=type(err).__name__,
                    func_name=func_name,
                    module_name=module_name,
                    context=context,
                    original_error=err,
                )

                # Log the error
                logging.log(log_level, f"[{func_name}] {error_msg}")

                # Notify UI if available
                if ui and not silent:
                    if hasattr(ui, "error"):
                        ui.error(error_msg)
                    elif hasattr(ui, "info"):
                        ui.info(f"Error in {func_name} → {err}")

                # Return or raise
                if raise_on_error:
                    raise
                return {"success": False, "error": error_msg, "data": None}

            except Exception as err:
                # Catch-all for unexpected errors
                error_msg = (
                    f"Unexpected error in '{func_name}' "
                    f"(module: {module_name}) → {err}"
                )
                logging.critical(f"[{func_name}] → {error_msg}")

                if ui and not silent:
                    if hasattr(ui, "error"):
                        ui.error(error_msg)
                    elif hasattr(ui, "info"):
                        ui.info(
                            f"[bold]CRITICAL ERROR[/bold] → {err}"
                        )

                if raise_on_error:
                    raise
                return {"success": False, "error": error_msg, "data": None}

        return wrapper

    return decorator


def _extract_context(args: Tuple, func_name: str) -> dict:
    """Extract useful context from function arguments."""
    context = {
        "arg_count": len(args),
        "first_arg_type": type(args[0]).__name__ if args else None,
    }

    # Try to get string representation of first argument
    if args:
        first_arg = args[0]
        try:
            if isinstance(first_arg, (str, int, float)):
                context["first_arg_preview"] = str(first_arg)[:100]
            elif hasattr(first_arg, "__name__"):
                context["first_arg_preview"] = first_arg.__name__[:100]
        except Exception:
            context["first_arg_preview"] = "<unrepresentable>"

    return context


def _format_error_message(
    error_type: str,
    func_name: str,
    module_name: str,
    context: dict,
    original_error: Exception,
) -> str:
    """Format error message consistently across the framework."""
    preview = context.get("first_arg_preview", "Unknown Input")

    if error_type == "ValueError":
        return (
            f"[{func_name}] Invalid input '{preview}' caused ValueError in "
            f"'{module_name}::{func_name}' → {original_error}"
        )
    elif error_type == "TypeError":
        return (
            f"[{func_name}] Type mismatch with '{preview}' caused TypeError in "
            f"'{module_name}::{func_name}' → {original_error}"
        )
    elif error_type == "AttributeError":
        return (
            f"[{func_name}] Missing attribute in '{module_name}::{func_name}' "
            f" → {original_error}"
        )
    elif error_type == "UnicodeDecodeError":
        return (
            f"[{func_name}] Binary data cannot be decoded in "
            f"'{module_name}::{func_name}' → {original_error}"
        )
    elif error_type == "KeyboardInterrupt":
        return f"[{func_name}] Program interrupted by user (Ctrl+C)..."
    elif error_type == "EOFError":
        return f"[{func_name}] An EOFError was received"
    else:
        return (
            f"[{func_name}] Error in '{module_name}::{func_name}' → "
            f"{original_error}"
        )
