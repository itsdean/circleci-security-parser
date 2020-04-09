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
from lib.output.OutputWrapper import OutputWrapper

class Reporter:
    """
    This class deals with the presenting of reported issues from their parser-standardised output to the relevant locations (i.e. .csv file,
    S3 bucket, etc.)
    """


    def upload(self, s3, full_path):
        bucket_name = os.getenv("PARSER_AWS_BUCKET_NAME")

        self.s3_path = self.repo + "/" + self.sha1 + "/" + self.job_name

        filename = ntpath.basename(full_path)
        parent_directory = ntpath.basename(Path(full_path).parent)

        tool_path = str(parent_directory) + "/" + str(filename)
        s3_tool_path = self.s3_path + "/" + tool_path

        self.output_wrapper.add(" - " + tool_path + " -> s3://" + bucket_name + "/" + s3_tool_path)

        s3.upload_file(
            Key=s3_tool_path,
            Filename=full_path,
            Bucket=bucket_name
        )

    def s3(self, files):
        bucket_name = os.getenv("PARSER_AWS_BUCKET_NAME")

        self.output_wrapper.set_title("S3")

        bucket_id = os.getenv("PARSER_AWS_AK_ID")

        s3 = boto3.client(
		"s3",
            aws_access_key_id=os.getenv("PARSER_AWS_AK_ID"),
            aws_secret_access_key=os.getenv("PARSER_AWS_SK")
        )
        self.output_wrapper.add("boto3.client connected")

        # Upload output produced by any tools
        self.output_wrapper.add("Uploading source files for reference")
        for input_file in files:
            full_path = input_file.name
            self.upload(s3, full_path)

        # Upload the parsed output
        self.output_wrapper.add("Uploading parsed output")
        self.upload(s3, self.csv_location)

        self.output_wrapper.add("[✓] Done!")
        self.output_wrapper.flush(verbose=False)

        # objects = s3.list_objects_v2(Bucket=bucket_name)
        # from pprint import pprint
        # for choices in objects["Contents"]:
        #     print(choices["Key"])

    def prepare_csv_name(self):
        """
        Creates the name of the file to save issue output to.
        The name can also include other values (such as the git repository name and branch) taken from CircleCI build variables.
        """

        csv_name = "parsed_output_"

        # Check if specific CircleCI environments are available and add their values to the output filename.
        if "CIRCLE_PROJECT_USERNAME" in os.environ:
            self.username = os.getenv("CIRCLE_PROJECT_USERNAME")
            csv_name += self.username + "_"
        if "CIRCLE_PROJECT_REPONAME" in os.environ:
            self.repo = os.getenv("CIRCLE_PROJECT_REPONAME").replace("_", "-")
            # csv_name += self.repo + "_"
        if "CIRCLE_BRANCH" in os.environ:
           self.branch = os.getenv("CIRCLE_BRANCH").replace("/", "-").replace("_", "-")
           csv_name += self.branch + "_"
        if "CIRCLE_JOB" in os.environ:
            self.job_name = os.getenv("CIRCLE_JOB").replace("/", "-").replace("_", "-")
            # csv_name += self.job_name + "_"
        # if "CIRCLE_BUILD_NUM" in os.environ:
        #     self.job_number = os.getenv("CIRCLE_BUILD_NUM")
        if "CIRCLE_SHA1" in os.environ:
            self.sha1 = os.getenv("CIRCLE_SHA1")

        # Obtain the current time in epoch format
        timestamp = int(
            time.time()
        )

        csv_name += str(timestamp) + ".csv"
        return csv_name


    def __init__(self, output_wrapper, issue_holder, o_folder):
        """
        Standard init procedure.
        """

        # Set up the filename_variables in preparation
        self.username = ""
        self.repo = ""
        self.branch = ""
        self.job_name = ""

        # Create the instances we will be calling throughout this class
        self.output_wrapper = output_wrapper
        self.issue_holder = issue_holder

        self.csv_name = self.prepare_csv_name()

        # Determine the exact path to save the parsed output to.
        self.csv_folder_name = o_folder
        self.csv_location = self.csv_folder_name + "/" + self.csv_name

        self.output_wrapper.set_title("Saving to: " + self.csv_location)
        self.output_wrapper.flush(verbose=True)


    def create_csv_report(self):
        """
        Obtains the current list of issues and prints them to a CSV file.
        """

        self.output_wrapper.clear()

        if self.issue_holder.size() == 0:

            self.output_wrapper.set_title("[x] There were no issues found during this job!")
            self.output_wrapper.add("- No report has been created.")
            self.output_wrapper.flush(verbose=True)

        else:

            deduplicated_findings = self.issue_holder.deduplicate()

            self.output_wrapper.set_title("Generating CSV report...")

            with open(self.csv_location, 'w+', newline="\n") as csv_file_object:
                writer = csv.DictWriter(csv_file_object, fieldnames=get_fieldnames())
                writer.writeheader()

                # Write a row in csv format for each finding that has been reported so far
                for finding in deduplicated_findings:
                    writer.writerow(finding)

            self.output_wrapper.add("[✓] Done!")

        self.output_wrapper.flush()
