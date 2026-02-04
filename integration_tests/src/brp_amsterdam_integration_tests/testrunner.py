import logging

import gevent
import settings
from locust import events
from locust.env import Environment
from locust.html import get_html_report
from locust.stats import stats_history, stats_printer
from user import BRPUser
from utils import get_token

logger = logging.getLogger(__name__)


@events.test_start.add_listener
def _(environment, **kwargs):
    environment.token = get_token()


@events.test_stop.add_listener
def analyze_results(environment, **kwargs):
    """Analyze results when test completes."""

    # Access overall statistics
    total_stats = environment.stats.total
    """
    logger.debug("\n=== Overall Statistics ===")
    logger.debug("Total Requests: %".format(total_stats.num_requests))
    logger.debug("Total Failures: {total_stats.num_failures}")
    logger.debug("Average Response Time: {total_stats.avg_response_time:.2f}ms")
    logger.debug("Min Response Time: {total_stats.min_response_time}ms")
    logger.debug("Max Response Time: {total_stats.max_response_time}ms")
    logger.debug(f"Requests/sec: {total_stats.total_rps:.2f}")

    # Percentiles
    logger.debug("\n=== Response Time Percentiles ===")
    for percentile in [0.50, 0.75, 0.90, 0.95, 0.99]:
        value = total_stats.get_response_time_percentile(percentile)
        logger.debug(f"P{int(percentile*100)}: {value:.0f}ms")

    # Per-endpoint statistics
    logger.debug("\n=== Per-Endpoint Statistics ===")
    for name, stats in environment.stats.entries.items():
        method = stats.method
        logger.debug(f"\n{method} {name}:")
        logger.debug(f"  Requests: {stats.num_requests}")
        logger.debug(f"  Failures: {stats.num_failures}")
        logger.debug(f"  Avg: {stats.avg_response_time:.0f}ms")
        logger.debug(f"  P95: {stats.get_response_time_percentile(0.95):.0f}ms")
    """
    if total_stats.num_failures > settings.ALLOWED_FAILURES:
        logger.error("BRP Amsterdam API Integration Tests Failed")


def run_tests(endpoints, **kwargs):
    # setup Environment and Runner
    env = Environment(user_classes=[BRPUser], events=events)
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

    with open("test.html", "w", encoding="utf-8") as html_file:
        html_file.write(get_html_report(environment=env))
