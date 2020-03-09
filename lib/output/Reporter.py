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


    def __init__(self, o_folder):
        """
        Standard init procedure.
        """

        # Create the instances we will be calling throughout this class
        self.output_wrapper = OutputWrapper()
        self.issue_holder = IssueHolder()

        self.csv_name = self.prepare_csv_name()

        # Determine the exact path to save the parsed output to.
        self.csv_folder_name = o_folder
        self.csv_location = self.csv_folder_name + "/" + self.csv_name

        self.output_wrapper.set_title("Saving to: " + self.csv_location)
        self.output_wrapper.flush()


    def get_issues(self):
        """
        Return the current list of issues.
        """
        return self.issue_holder.get_issues()


    def add(
        self,
        issue_type,
        tool_name,
        title,
        description,
        location,
        recommendation,
        filename = "",
        raw_output = "n/a",
        severity = "",
        cve_value = "n/a",
    ):
        """
        Inserts a new issue to the list; the parameters force a reporting standard to be followed (i.e. each must have the first six parameters as "headings" in a report)
        """

        self.issue_holder.add(
            Issue(
                issue_type,
                tool_name,
                title,
                description,
                location,
                recommendation,
                # ifile_name=filename,
                raw_output=raw_output,
                severity=severity,
                cve_value=cve_value
            )
        )


    def deduplicate(self):
        """
        Goes through the list of submitted issues and removes any issues that have been reported more than once.

        The description and location of each issue is merged together and hashed - if this hash has not been dealt with (this parsing round) before then we'll accept it, otherwise ignore it.
        """

        self.output_wrapper.set_title("Deduplicating...")

        # Create an empty list that will contain the unique issues.
        deduplicated_findings = []

        # Use a secondary list that will only contain issue descriptions as
        # keys. We'll use hashes of the combination of the description and 
        # location as existence oracles
        issue_hash_oracle = []

        # Make a new list object and hard copy all current issues to that
        # object. Iterate through it.
        for element in list(self.issue_holder.get_issues()):

            # Get the issue in dictionary format
            issue = element.get()

            # Generate a hash from fields of the issue. This will be used to uniquely identify that issue
            issue_hash = hashlib.sha256(
                # issue["description"].encode("utf-8") + b":" + issue["location"].encode("utf-8")
                issue["description"].encode("utf-8") + b":" + issue["location"].encode("utf-8")
            ).hexdigest()

            # Check if the description for the issue's not already in the lookup table list
            if issue_hash not in issue_hash_oracle:

                # If we've reached this line, then it's a new issue we haven't seen before and we can report it.
                # Add the description to the oracle list
                issue_hash_oracle.append(issue_hash)

                # Add the full issue to the new list
                deduplicated_findings.append(issue)

        self.output_wrapper.add("- Array size: " + str(self.issue_holder.size()))
        self.output_wrapper.add("- Array size after deduplication: " + str(len(deduplicated_findings)))

        return deduplicated_findings


    def create_csv_report(self):
        """
        Obtains the current list of issues and prints them to a CSV file.
        """

        if self.issue_holder.size() == 0:

            self.output_wrapper.set_title("[x] There were no issues found during this job!")
            self.output_wrapper.add("- No report has been created.")
            self.output_wrapper.flush()

        else:

            self.output_wrapper.set_title("Generating CSV report...")

            deduplicated_findings = self.deduplicate()

            with open(self.csv_location, 'w+', newline="\n") as csv_file_object:
                writer = csv.DictWriter(csv_file_object, fieldnames=get_fieldnames())
                writer.writeheader()

                # Write a row in csv format for each finding that has been reported so far
                for finding in deduplicated_findings:
                    writer.writerow(finding)

            self.output_wrapper.add("[✓] Done!")

        self.output_wrapper.flush()
