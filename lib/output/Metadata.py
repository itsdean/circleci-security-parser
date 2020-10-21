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
            self.payload["username"] = self.username

        if "CIRCLE_PROJECT_USERNAME" in os.environ:
            self.project_username = os.getenv("CIRCLE_PROJECT_USERNAME")
            self.l.debug(f"project username: {self.project_username}")
            self.payload["project_username"] = self.project_username
            
        if "CIRCLE_PROJECT_REPONAME" in os.environ:
            self.repository = os.getenv("CIRCLE_PROJECT_REPONAME")
            self.l.debug(f"repository: {self.repository}")
            self.payload["repository"] = self.repository

        if "CIRCLE_BRANCH" in os.environ:
            self.branch = os.getenv("CIRCLE_BRANCH").replace("/", "-").replace("_", "-")
            self.l.debug(f"branch: {self.branch}")
            self.payload["branch"] = self.branch

        if "CIRCLE_SHA1" in os.environ:
            self.commit_hash = os.getenv("CIRCLE_SHA1")
            self.l.debug(f"commit hash: {self.commit_hash}")
            self.payload["commit_hash"] = self.commit_hash

        if "CIRCLE_PULL_REQUEST" in os.environ:
            self.is_pr = True
            self.pr_url = os.getenv("CIRCLE_PULL_REQUEST")
            self.l.debug(f"PR URL: {self.pr_url}")
            self.pr_number = int(self.pr_url.split("pull/")[1])
            self.payload["pr_info"] = {
                "pr_url": self.pr_url,
                "pr_number": self.pr_number
            }
        else:
            self.is_pr = False
        self.payload["is_pr"] = self.is_pr

        if "CIRCLE_JOB" in os.environ:
            self.job = os.getenv("CIRCLE_JOB").replace("/", "-").replace("_", "-")
            self.payload["circleci_info"] = {
                "job": self.job
            }
        print()


    def __get_aws_credentials(self):
        self.l.info("Looking for AWS S3 bucket environment variables..")
        if "PARSER_AWS_BUCKET_NAME" in os.environ:
            self.aws_bucket_name = os.getenv("PARSER_AWS_BUCKET_NAME")
            self.payload["aws"] = {
                "aws_bucket_name": self.aws_bucket_name
            }
            self.l.debug(f"AWS Bucket Name: {self.aws_bucket_name}")
        else:
            self.l.error("The PARSER_AWS_BUCKET_NAME environment variable was not found!")
            self.c.upload_to_aws = False
        if "PARSER_AWS_AK_ID" in os.environ:
            self.aws_access_key_id = os.getenv("PARSER_AWS_AK_ID")
            self.l.debug("AWS access key found")
        else:
            self.l.error("The PARSER_AWS_AK_ID environment variable was not found!")
            self.c.upload_to_aws = False
        if "PARSER_AWS_SK" in os.environ:
            self.aws_secret_key = os.getenv("PARSER_AWS_SK")
            self.l.debug("AWS secret key found")
        else:
            self.l.error("The PARSER_AWS_SK environment variable was not found!")
            self.c.upload_to_aws = False
        print()


    def __init__(self, logger, config):
        self.payload = {}

        self.l = logger

        self.c = config
        self.payload["fail_threshold"] = self.c.fail_threshold

        self.username = ""
        self.repository = ""
        self.branch = ""
        self.commit_hash = ""
        self.job = ""

        if "CIRCLECI" in os.environ:
            self.is_circleci = True
            self.__get_circleci_environment_variables()
        else:
            self.is_circleci = False
        self.payload["is_circleci"] = self.is_circleci

        self.aws_bucket_name = ""
        self.aws_access_key_id = ""
        self.aws_secret_key = ""

        if self.c.upload_to_aws:
            self.__get_aws_credentials()