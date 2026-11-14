from rich.console import Console
from rich.panel import Panel

console = Console()
DISCLAIMER = (
    "SENTINEL is for authorized security testing only. You are solely responsible for obtaining "
    "written authorization for every target."
)


def show_banner() -> None:
    console.print(
        Panel.fit(
            "[bold cyan]SENTINEL[/bold cyan] · offline, scope-enforced security simulation",
            subtitle=DISCLAIMER,
            border_style="cyan",
        )
    )
