import subprocess
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel


# تهيئة rich console
console = Console()

def run_command(command):
    try:
        result = subprocess.run(command, check=True, text=True, capture_output=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        console.print(Panel(f"[red]Error:[/red] {e.stderr}", title="Error", expand=False))
        return None

def main():
    console.print(Panel("[yellow]GitHub Auto Update Script[/yellow]", title="Welcome", expand=False))
    
    # طلب رسالة الالتزام
    commit_message = Prompt.ask("[[green]+[/green]] Enter commit message")

    commands = [
        ["git", "add", "."],
        ["git", "commit", "-m", commit_message],
        ["git", "push"]
    ]

    for command in commands:
        output = run_command(command)
        if output:
            console.print(Panel(f"[green]Output:[/green]\n{output}", title=f"Running {' '.join(command)}", expand=False))
    
    console.print(Panel("[blue]All done![/blue]", title="Success", expand=False))

if __name__ == "__main__":
    main()