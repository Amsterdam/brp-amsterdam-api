import enum

import click


class Endpoint(enum.Enum):
    personen = "personen"
    bewoning = "bewoning"
    verblijfplaatshistorie = "verblijfplaatshistorie"
    all = "all"


@click.command()
@click.option(
    "-e", "--endpoint", type=click.Choice(Endpoint), default=Endpoint.all, help="Endpoint to test"
)
@click.option("-l", "--load-test", type=bool, default=False, help="Perform a load test")
def run_tests(endpoint: Endpoint, load_test: bool):
    print(endpoint)
    print(load_test)


if __name__ == "__main__":
    run_tests()
