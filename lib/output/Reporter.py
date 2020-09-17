import boto3
import csv
import glob
import hashlib
import ntpath
import os
import time

from dotenv import load_dotenv
load_dotenv()

from pathlib import Path

from lib.issues.Issue import Issue, get_fieldnames
from lib.issues.IssueHolder import IssueHolder

class Reporter:
    """
    This class deals with the presenting of reported issues from their parser-standardised output to the relevant locations (i.e. .csv file,
    S3 bucket, etc.)
    """

    def upload(self, s3, full_path):
        bucket_name = os.getenv("PARSER_AWS_BUCKET_NAME")

        self.s3_path = self.repo
        self.s3_path += "/" + self.sha1

        # If we're dealing with a pull request, then add it to the sha1 commit.
        # We'll split it and deal with it in the Lambda (as this may not
        # even be a pull request).

        # example url format:
        # https://github.com/CyDefUnicorn/OSCP-Archives/pull/2
        if "CIRCLE_PULL_REQUEST" in os.environ:
            # split the url to just get the PR number
            pr_url = os.getenv("CIRCLE_PULL_REQUEST")
            pr_number = pr_url.split("pull/")[1]
            self.s3_path += "_" + pr_number

        self.s3_path += "/" + str(self.timestamp)
        self.s3_path += "/" + self.job_name

        filename = full_path.split("/")[-1]
        path = Path(full_path)
        parent_directory = str(path.parent).split("/")[-1]

        tool_path = str(parent_directory) + "/" + str(filename)
        s3_tool_path = self.s3_path + "/" + tool_path

        self.l.debug(f"> {tool_path} -> s3://{bucket_name}/{s3_tool_path}")

        s3.upload_file(
            Key=s3_tool_path,
            Filename=full_path,
            Bucket=bucket_name
        )

    def upload_to_s3(self, input_files):
        bucket_name = os.getenv("PARSER_AWS_BUCKET_NAME")
        print()
        self.l.info("Uploading to S3 bucket {bucket_name}")

        bucket_id = os.getenv("PARSER_AWS_AK_ID")
        s3 = boto3.client(
		"s3",
            aws_access_key_id=os.getenv("PARSER_AWS_AK_ID"),
            aws_secret_access_key=os.getenv("PARSER_AWS_SK")
        )
        self.l.debug("boto3.client instantiated")

        # Upload output produced by any tools
        self.l.info("Uploading original tool output files")
        for input_file in input_files:
            full_path = input_file.name
            self.upload(s3, full_path)

        # Upload the parsed output
        self.l.info("Uploading parsed output")
        self.upload(s3, self.csv_location)

        self.l.info("Upload complete")

    def prepare_csv_name(self):
        """
        Creates the name of the file to save issue output to.
        The name can also include other values (such as the git repository name and branch) taken from CircleCI build variables.
        """

        csv_name = "output_"

        # Check if specific CircleCI environments are available and add their values to the output filename.
        if "CIRCLE_PROJECT_USERNAME" in os.environ:
            csv_name += os.getenv("CIRCLE_PROJECT_USERNAME") + "_"
            # csv_name += self.username + "_"
        if "CIRCLE_PROJECT_REPONAME" in os.environ:
            self.repo = os.getenv("CIRCLE_PROJECT_REPONAME").replace("_", "-")
            # csv_name += self.repo + "_"
        if "CIRCLE_BRANCH" in os.environ:
            csv_name += os.getenv("CIRCLE_BRANCH").replace("/", "-").replace("_", "-") + "_"
        if "CIRCLE_JOB" in os.environ:
            self.job_name = os.getenv("CIRCLE_JOB").replace("/", "-").replace("_", "-")
            csv_name += self.job_name + "_"
        if "CIRCLE_SHA1" in os.environ:
            self.sha1 = os.getenv("CIRCLE_SHA1")

        # Obtain the current time in epoch format
        timestamp = int(
            time.time()
        )

        self.timestamp = timestamp

        csv_name += str(timestamp) + ".csv"
        return csv_name


    def __init__(self, logger, issue_holder, o_folder):
        """
        Standard init procedure.
        """

        self.l = logger

        # # Set up the filename_variables in preparation
        self.repo = ""
        self.job_name = ""
        self.sha1 = ""

        # Create the instances we will be calling throughout this class
        self.issue_holder = issue_holder

        self.csv_name = self.prepare_csv_name()

        # Determine the exact path to save the parsed output to.
        self.csv_location = o_folder + "/" + self.csv_name


    def create_csv_report(self):
        """
        Obtains the current list of issues and prints them to a CSV file.
        """

        if self.issue_holder.size() == 0:
            self.l.warning("There were no issues found - no report has been created.")
            return False

        else:
            deduplicated_findings = self.issue_holder.deduplicate()

            self.l.info(f"Generating CSV report at {self.csv_location}")

            with open(self.csv_location, 'w+', newline="\n") as csv_file_object:
                writer = csv.DictWriter(csv_file_object, fieldnames=get_fieldnames())
                writer.writeheader()

                # Write a row in csv format for each finding that has been reported so far
                for finding in deduplicated_findings:
                    writer.writerow(finding)

            self.l.info("Report created\n")
            return True
