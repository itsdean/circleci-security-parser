import os


class Metadata:
    """
    This class stores and outputs metadata relevant to the current parse.
    """

    def __get_circleci_environment_variables(self):
        self.l.info("Looking for CircleCI environment variables...")
        if "CIRCLE_USERNAME" in os.environ:
            self.username = os.getenv("CIRCLE_USERNAME")
            self.l.debug(f"username: {self.username}")
        if "CIRCLE_PROJECT_REPONAME" in os.environ:
            self.repository = os.getenv("CIRCLE_PROJECT_REPONAME")
            self.l.debug(f"repository: {self.repository}")
        if "CIRCLE_BRANCH" in os.environ:
            self.branch = os.getenv("CIRCLE_BRANCH").replace("/", "-").replace("_", "-")
            self.l.debug(f"branch: {self.branch}")
        if "CIRCLE_SHA1" in os.environ:
            self.commit_hash = os.getenv("CIRCLE_SHA1")
            self.l.debug(f"commit hash: {self.commit_hash}")
        if "CIRCLE_PULL_REQUEST":
            self.is_pr = True
            self.pr_url = os.getenv("CIRCLE_PULL_REQUEST")
            self.l.debug(f"PR URL: {self.pr_url}")
            self.pr_number = int(self.pr_url.split("pull/")[1])


        # if "CIRCLE_PROJECT_USERNAME" in os.environ:
            # csv_name += os.getenv("CIRCLE_PROJECT_USERNAME") + "_"
            # csv_name += self.username + "_"
        # if "CIRCLE_PROJECT_REPONAME" in os.environ:
        #     self.repo = os.getenv("CIRCLE_PROJECT_REPONAME").replace("_", "-")
            
        #     # csv_name += self.repo + "_"
        # # if "CIRCLE_BRANCH" in os.environ:
        #     # csv_name += os.getenv("CIRCLE_BRANCH").replace("/", "-").replace("_", "-") + "_"

        # if "CIRCLE_JOB" in os.environ:
        #     self.job_name = os.getenv("CIRCLE_JOB").replace("/", "-").replace("_", "-")
        #     # csv_name += self.job_name + "_"
        # if "CIRCLE_SHA1" in os.environ:
        #     self.sha1 = os.getenv("CIRCLE_SHA1")

        print()


    def __init__(self, logger, config):
        self.l = logger

        self.payload = {}

        self.username = ""
        self.repository = ""
        self.branch = ""
        self.commit_hash = ""

        self.is_pr = False
        self.pr_url = ""
        self.pr_number = 0

        # self.repository_name = ""
        # self.job_name = ""

        self.__get_circleci_environment_variables()

        if config.upload_to_aws:
            self.__get_aws_credentials()

        self.payload = {
            "repository": self.repository,
            "branch": self.branch,
            "username": self.username,
            "commit_hash": self.commit_hash,
            "pr": self.is_pr
        }

        # exit()

#  todo: create output file
# output file will store:
# - username
# - 
