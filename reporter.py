import time
import csv
import os
import constants


class Reporter:


    def __init__(self, o_folder):
        self.temp_findings = []

        # Set up the filename_variables in preparation
        username = ""
        repo = ""
        job_name = ""

        # Check if specific CircleCI environments are available and add their values to the output filename.
        if "CIRCLE_PROJECT_USERNAME" in os.environ:
            username = os.getenv("CIRCLE_PROJECT_USERNAME") + "_"
        if "CIRCLE_PROJECT_REPONAME" in os.environ:
            repo = os.getenv("CIRCLE_PROJECT_REPONAME").replace("_", "-") + "_"
        if "CIRCLE_JOB" in os.environ:
            job_name = os.getenv("CIRCLE_JOB").replace("/", "-").replace("_", "-") + "_"

        # Determine the exact path to save the parsed output to.
        self.filename = "parsed_output_" + \
                        username + \
                        repo + \
                        job_name + \
                        str(int(time.time())) + ".csv"
        self.o_folder = o_folder
        self.o_file = self.o_folder + "/" + self.filename
        print(">" * constants.SEPARATOR_LENGTH + "\nSaving to: " + self.o_file + "\n" + "<" * constants.SEPARATOR_LENGTH + "\n")


    def get(self):
        return self.temp_findings


    """
    Inserts a new issue to the list; the parameters force a reporting standard to be followed (i.e. each must have the first six parameters as "headings" in a report)
    """
    def add(
        self,
        issue_type,
        tool_name,
        title,
        description,
        location,
        recommendation,
        ifile_name = "",
        raw_output = "n/a",
        severity = "n/a",
        cve_value = "n/a",
    ):
        self.temp_findings.append(
            {
                "issue_type": issue_type,
                "tool_name": tool_name,
                "title": title,
                "severity": severity,
                "description": description,
                "cve_value": cve_value,
                "location": location,
                "recommendation": recommendation,
                "raw_output": raw_output
            }
        )


    def deduplicate(self):
        """
        Goes through the list of submitted issues and removes any issues that have been reported more than once.

        The description and location of each issue is merged together and hashed - if this hash has not been dealt with (this parsing round) before then we'll accept it, otherwise ignore it.
        """

        import hashlib

        print("- Deduplicating...")

        # Obtain a temporary version of our current (potentially duplicated) findings.
        tmp_duped_array = self.get()

        # Create an empty list that will contain the unique issues.
        deduped_findings = []

        # Use a secondary list that will only contain issue descriptions as keys.
        # We'll use hashes of the combination of the description and location as existence oracles
        duplicate_oracle = []

        # For each finding in the original list...
        for issue in tmp_duped_array:

            issue_hash = hashlib.sha256(
                # issue["description"].encode("utf-8") + b":" + issue["location"].encode("utf-8")
                issue["description"].encode("utf-8") + b":" + issue["location"].encode("utf-8")
            ).hexdigest()

            # Check if the description for the issue's not already in the lookup table list
            if issue_hash not in duplicate_oracle:

                # If we've reached this line, then it's a new issue we haven't seen before and we can report it.
                # Add the description to the oracle list
                duplicate_oracle.append(issue_hash)

                # Add the full issue to the new list
                deduped_findings.append(issue)

        print("- Array size: " + str(len(tmp_duped_array)))
        print("- Array size after deduplication: " + str(len(deduped_findings)))

        return deduped_findings


    def create_report(self):

        if len(self.get()) == 0:
            print("- There were no issues found during this job.")
            print("- Skipping CSV report creation...")
            exit(0)

        print(">" * constants.SEPARATOR_LENGTH + "\nAttempting to generate CSV report...\n" + "-" * constants.SEPARATOR_LENGTH)

        self.temp_findings = self.deduplicate()

        fieldnames = [
            "issue_type",
            "tool_name",
            "title",
            "severity",
            "description",
            "cve_value",
            "location",
            "recommendation",
            "raw_output"
        ]

        with open(self.o_file, 'w+', newline="\n") as open_o_file:
            writer = csv.DictWriter(open_o_file, fieldnames=fieldnames)
            writer.writeheader()

            # Write a row in csv format for each finding that has been reported so far
            for finding in self.temp_findings:
                writer.writerow(finding)

        print("- [✓] Done!\n" + "<" * constants.SEPARATOR_LENGTH)
