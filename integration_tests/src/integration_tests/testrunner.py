import logging
import sys

import gevent
from locust import events
from locust.env import Environment
from locust.stats import stats_history, stats_printer

from integration_tests import settings
from integration_tests.user import BRPUser
from integration_tests.utils import get_token

logger = logging.getLogger(__name__)


@events.test_start.add_listener
def _(environment, **kwargs):
    environment.token = get_token()


@events.test_stop.add_listener
def analyze_results(environment, **kwargs):
    """Analyze results when test completes."""

    # Access overall statistics
    total_stats = environment.stats.total

    if total_stats.num_failures > settings.ALLOWED_FAILURES:
        logger.error("BRP Amsterdam API Integration Tests Failed")
        sys.exit(1)
    else:
        logger.info("BRP Amsterdam API Integration Tests Passed")


def run_tests(endpoints, **kwargs):
    # setup Environment and Runner
    env = Environment(user_classes=[BRPUser], events=events, tags=endpoints)
    runner = env.create_local_runner()

    # start a greenlet that periodically outputs the current stats
    gevent.spawn(stats_printer(env.stats))

    # start a greenlet that save current stats to history
    gevent.spawn(stats_history, env.runner)

    # start the test
    runner.start(user_count=1, spawn_rate=10)

    # in 30 seconds stop the runner
    gevent.spawn_later(10, runner.quit)

    # wait for the greenlets
    runner.greenlet.join()
