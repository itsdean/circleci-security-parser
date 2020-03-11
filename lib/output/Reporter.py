import csv
import hashlib
import os
import time

from lib.issues.Issue import Issue, get_fieldnames
from lib.issues.IssueHolder import IssueHolder
from lib.output.OutputWrapper import OutputWrapper

class Reporter:
    """
    This class deals with the presenting of reported issues from their parser-standardised output to the relevant locations (i.e. .csv file,
    S3 bucket, etc.)
    """


    def prepare_csv_name(self):
        """
        Creates the name of the file to save issue output to.
        The name can also include other values (such as the git repository name and branch) taken from CircleCI build variables.
        """

        # Set up the filename_variables in preparation
        username = ""
        repo = ""
        branch = ""
        job_name = ""

        # Check if specific CircleCI environments are available and add their values to the output filename.
        if "CIRCLE_PROJECT_USERNAME" in os.environ:
            username = os.getenv("CIRCLE_PROJECT_USERNAME") + "_"
        if "CIRCLE_PROJECT_REPONAME" in os.environ:
            repo = os.getenv("CIRCLE_PROJECT_REPONAME").replace("_", "-") + "_"
        if "CIRCLE_BRANCH" in os.environ:
            branch = os.getenv("CIRCLE_BRANCH").replace("/", "-").replace("_", "-") + "_"
        if "CIRCLE_JOB" in os.environ:
            job_name = os.getenv("CIRCLE_JOB").replace("/", "-").replace("_", "-") + "_"

        # Obtain the current time in epoch format
        timestamp = int(
            time.time()
        )

        csv_name = "parsed_output_" + \
                    username + \
                    repo + \
                    branch + \
                    job_name + \
                    str(timestamp) + ".csv"
        return csv_name


    def __init__(self, output_wrapper, issue_holder, o_folder):
        """
        Standard init procedure.
        """

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
