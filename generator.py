import typer
import describer
import template

app = typer.Typer()


@app.command()
def version():
    """
    Displays the current version of the CLI
    """
    print("0.0.1-beta")


@app.command()
def read(path: str):
    """
    Read the content of the certificates
    """
    if len(path) == 0:
        raise Exception("path must not be empty")
    f = open(
        file=path,
        mode="r")
    s = f.read()
    b = s.encode(encoding='utf-8')
    describer.read(data=b)


@app.command()
def generate(path: str):
    """
    Generates certificates according to a YAML template
    """
    if len(path) == 0:
        raise Exception("path must not be empty")
    template.read_template_file(path=path)


if __name__ == "__main__":
    app()
