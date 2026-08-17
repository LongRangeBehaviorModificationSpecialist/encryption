from rich.console import Console
from rich.traceback import install


console = Console()
install(show_locals=True, console=console)