import boto3
import csv
import glob
import hashlib
import json
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

        self.s3_path = f"{self.m.repository}/{self.m.commit_hash}"
        
        # If we're dealing with a pull request, then add it to the sha1 commit.
        # We'll split it and deal with it in the Lambda (as this may not
        # even be a pull request).
        # if self.m.is_pr:
        #     self.s3_path += f"_{self.m.pr_number}"

        self.s3_path += f"/{self.timestamp}"

        if self.m.job:
            self.s3_path += f"/{self.m.job}"

        filename = full_path.split("/")[-1]
        path = Path(full_path)
        parent_directory = str(path.parent).split("/")[-1]

        tool_path = str(parent_directory) + "/" + str(filename)
        s3_tool_path = self.s3_path + "/" + tool_path

        self.l.debug(f"> {tool_path} -> s3://{self.m.aws_bucket_name}/{s3_tool_path}")

        s3.upload_file(
            Key=s3_tool_path,
            Filename=full_path,
            Bucket=self.m.aws_bucket_name
        )


    def upload_to_s3(self):
        self.l.info(f"Uploading to S3 bucket {self.m.aws_bucket_name}")
        s3 = boto3.client(
            "s3",
            aws_access_key_id = self.m.aws_access_key_id,
            aws_secret_access_key = self.m.aws_secret_key
        )
        self.l.debug("boto3.client instantiated")

        # Upload output produced by any tools
        self.l.info("Uploading original tool output files")
        for input_file in self.m.input_files:
            full_path = input_file.name
            self.upload(s3, full_path)

        # Upload the parsed output
        self.l.info("Uploading parsed output")
        self.upload(s3, self.csv_location)

        self.l.info("Uploading metadata")
        self.upload(s3, self.metadata_filepath)

        self.l.info("Upload complete")


    def prepare_csv_name(self):
        """
        Creates the name of the file to save issue output to.
        The name can also include other values (such as the git repository name and branch) taken from CircleCI build variables.
        """

        csv_name = f"parser_output"

        if self.m.is_circleci:
            csv_name += f"_circleci"
            csv_name += f"_{self.m.repository}"

        csv_name += f"_{self.timestamp}.csv"
        
        return csv_name


    def __init__(self, logger, metadata, issue_holder):
        """
        Standard init procedure.
        """

        self.l = logger
        self.m = metadata

        self.issue_holder = issue_holder

        self.timestamp = int(time.time())
        self.m.payload["timestamp"] = self.timestamp

        # Determine the exact path to save the parsed output to.
        self.csv_name = self.prepare_csv_name()
        self.csv_location = f"{self.m.output_path}/{self.csv_name}"


    def create_csv_report(self):
        """
        Obtains the current list of issues and prints them to a CSV file.
        """

        self.l.info(f"Generating CSV report at {self.csv_location}")
        with open(self.csv_location, 'w+', newline="\n", encoding="utf-8") as csv_file_object:
            writer = csv.DictWriter(csv_file_object, fieldnames=get_fieldnames())
            writer.writeheader()

            if self.issue_holder.size() > 0:
                deduplicated_findings = self.issue_holder.deduplicate()
                self.m.payload["issue_count"] = len(deduplicated_findings)

                for finding in deduplicated_findings:
                    writer.writerow(finding)
            else:
                self.m.payload["issue_count"] = 0

        self.l.info("Report created\n")
        return True

    def generate_metadata_file(self):
        metadata_filename = f"parser_metadata_{self.timestamp}.json"
        self.metadata_filepath = f"{self.m.output_path}/{metadata_filename}"

        with open(self.metadata_filepath, "w") as metadata_file:
            json.dump(self.m.payload, metadata_file)
