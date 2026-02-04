from locust import TaskSet, task


class BaseTaskSet(TaskSet):
    path: str = ""

    @property
    def url(self):
        return self.user.base_url + self.path

    @task
    def stop(self):
        self.interrupt()
