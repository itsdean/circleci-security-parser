import time
import csv
import os

"""

FYI

csv format

report_type - secrets, container, code, etc.
tool - tool used
name - issue that tool reported + rating where available
description - issue description if availabke?
location - location of finding
raw_output - raw finding output for triaging, along with filename

"""
class Reporter:


    def __init__(self, o_folder):
        self.temp_findings = []

        # Determine the exact path to save the parsed output to.
        self.filename = "parsed_output_" + str(int(time.time())) + ".csv"
        self.o_folder = o_folder
        self.o_file = self.o_folder + "/" + self.filename


    def add_finding(self, report_type="", tool="", name="", description="", location="", raw_output="", i_file=""):
        # Get the filename to save with the raw output
        filename = os.path.basename(i_file.name)

        # Add the finding to the list to be reported
        self.temp_findings.append({
            "report_type": report_type,
            "tool": tool,
            "name": name,
            "description": description,
            "location": location,
            "raw_output": filename + " - " + str(raw_output)
        })


    def create_report(self):
        print("Writing CSV report...")

        fieldnames = [
            "report_type",
            "tool",
            "name",
            "description",
            "location",
            "raw_output"
        ]

        with open(self.o_file, 'w+', newline="\n") as open_o_file:
            writer = csv.DictWriter(open_o_file, fieldnames=fieldnames)
            writer.writeheader()

            # Write a row in csv format for each finding that has been reported so far
            for finding in self.temp_findings:
                writer.writerow(finding)

        print("Done!")