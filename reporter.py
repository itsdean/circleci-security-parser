import time
import csv
import os
import constants

"""
FYI

csv format

issue_type = dependencies, secrets, etc.
tool_name = Snyk [Node], Snyk [Image], burrow, etc.
title = "Hardcoded Credentials"
severity = how bad?
description = what's the issue?
location = where?
recommendation = how to fix?
CVE = CVE number if it exists. Can be left blank I suppose
raw_output = what we just parsed, in case we missed something outhats

"""
class Reporter:


    def __init__(self, o_folder):
        self.temp_findings = []

        # Check if specific CircleCI environments are available and add their values to the output filename.
        if "CIRCLE_PROJECT_USERNAME" in os.environ:
            username = os.getenv("CIRCLE_PROJECT_USERNAME") + "_"
        else:
            username = ""
        if "CIRCLE_PROJECT_REPONAME" in os.environ:
            repo = os.getenv("CIRCLE_PROJECT_REPONAME").replace("_", "-") + "_"
        else:
            repo = ""
        if "CIRCLE_JOB" in os.environ:
            job_name = os.getenv("CIRCLE_JOB").replace("/", "-").replace("_", "-") + "_"
        else:
            job_name = ""

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
    Inserts a new issue to the list; the parameters force a reporting standard to be followed (i.e. each must have the first six parameters as "headings" in a report)x
    """
    def add(
        self,
        issue_type,
        tool_name,
        title,
        description,
        location,
        recommendation,
        ifile_name,
        raw_output = "n/a",
        severity = "unknown",
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
        print("- Deduplicating...")
        tmp_duped_array = self.get()
        deduped_findings = []
        raw_output_key = []

        for issue in tmp_duped_array:
            if issue['description'] not in raw_output_key:
                # print(issue['raw_output'])
                raw_output_key.append(issue['description'])
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
