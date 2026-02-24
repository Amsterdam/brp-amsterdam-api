import logging

import click

from integration_tests.testrunner import run_tests

logging.basicConfig(format="%(levelname)s:%(message)s", level=logging.INFO)


ENDPOINTS = [
    "personen",
    "bewoningen",
    "verblijfsplaatshistorie",
]


@click.command()
@click.option(
    "-e",
    "--endpoints",
    type=click.Choice(ENDPOINTS),
    multiple=True,
    default=ENDPOINTS,
    help="Endpoints to test",
)
@click.option("-l", "--load-test", type=bool, default=False, help="Perform a load test")
def cli(endpoints: list, load_test: bool):
    run_tests(endpoints)
