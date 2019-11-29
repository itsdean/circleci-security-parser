import time
import csv
import os
import constants

"""
FYI

csv format

report_type - secrets, container, code, etc.
tool - tool used
name - issue that tool reported + rating where available
description - issue description if availabke?
location - location of finding
raw_output - raw finding raw_output for triaging, along with filename

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


    def get_existing_findings(self):
        return self.temp_findings


    def add_finding(self, report_type="", tool="", name="", description="", recommendation = "", location="", raw_output="", i_file=""):
        # Get the filename to save with the raw output
        filename = os.path.basename(i_file.name)

        # Add the finding to the list to be reported
        self.temp_findings.append({
            "report_type": report_type,
            "tool": tool,   
            "name": name,
            "description": description,
            "recommendation": recommendation,
            "location": location,
            "raw_output": filename + " - " + str(raw_output)
        })


    def deduplicate(self):
        print("- Deduplicating...")
        tmp_duped_array = self.get_existing_findings()
        deduped_findings = []
        raw_output_key = []

        for issue in tmp_duped_array:
            if issue['raw_output'] not in raw_output_key:
                # print(issue['raw_output'])
                raw_output_key.append(issue['raw_output'])
                deduped_findings.append(issue)

        print("- Array size: " + str(len(tmp_duped_array)))
        print("- Array size after deduplication: " + str(len(deduped_findings)))

        return deduped_findings

    def create_report(self):


        if len(self.get_existing_findings()) == 0:
            print("- There were no issues found during this job.")
            print("- Skipping CSV report creation...")
            exit(0)

        print(">" * constants.SEPARATOR_LENGTH + "\nAttempting to generate CSV report...\n" + "-" * constants.SEPARATOR_LENGTH)

        self.temp_findings = self.deduplicate()

        fieldnames = [
            "report_type",
            "tool",
            "name",
            "description",
            "recommendation",
            "location",
            "raw_output"
        ]

        with open(self.o_file, 'w+', newline="\n") as open_o_file:
            writer = csv.DictWriter(open_o_file, fieldnames=fieldnames)
            writer.writeheader()

            # Write a row in csv format for each finding that has been reported so far
            for finding in self.temp_findings:
                writer.writerow(finding)

        print("- [✓] Done!\n" + "<" * constants.SEPARATOR_LENGTH)
