
# -*- coding: utf-8 -*-

import json
import os
import re

from pprint import pprint


class CoreParser:
    """
    Redirects files to their respective parsers to be processed.
    """

    parsed_tools = {
        "gosec": "gosec",
        "nancy": "nancy",
        "burrow": "burrow",
        "gitleaks": "gitleaks",
        "Snyk [Node]": "snyk_node",
    }

    def gosec(self, i_file):
        from lib.parsers import gosec
        gosec.parse(i_file, self.issue_holder, self.output_wrapper)

    def nancy(self, i_file):
        from lib.parsers import nancy
        nancy.parse(i_file, self.issue_holder, self.output_wrapper)

    def burrow(self, burrow_file):
        from lib.parsers import burrow
        burrow.parse(burrow_file, self.issue_holder, self.output_wrapper)

    def gitleaks(self, gitleaks_file):
        from lib.parsers import gitleaks
        gitleaks.parse(gitleaks_file, self.issue_holder, self.output_wrapper)

    def snyk_node(self, i_file):
        from lib.parsers import snyk
        snyk.parse_node(i_file, self.issue_holder, self.output_wrapper)

    def get_file_source(self, i_file):
        """
        Iterates through a dictionary of tools that can be parsed and compares their associated filename patterns with the file currently being processed.
        """

        self.output_wrapper.set_title(
            "Parsing: " + os.path.basename(i_file.name))

        # Get the tool name ("Snyk [Node]" for example) and its associated matching filename ("snyk_node"), both from parsed_tools in KV format
        for toolname, filename_pattern in self.parsed_tools.items():
            # Alright, we've found a file from a tool that we support
            if filename_pattern in i_file.name:
                # Lets obtain a link to the correct tool parser we'll be using. Thanks getattr, you're the best!
                self.output_wrapper.add("Tool identified: " + toolname)
                # We could squash the below into one line but it's more confusing to understand if you don't know getattr.
                file_parser_method = getattr(self, filename_pattern)
                file_parser_method(i_file)

        self.output_wrapper.flush(verbose=True)

    def check_threshold(self, fail_threshold):
        """
        Check if an issue severity threshold has been set and if so, return an error code equal to a map against the issues to be reported.

        The error code returned depends on the issue with the highest severity. 5 = critical, 4 = high, etc. 

        tl;dr if fail_threshold = "high", return 4 if we only find high issues, and return 5 if we find a critical. if don't find either, return 0.
        """

        # Store the return value of the script
        error_code = 0

        # Only go down this route if a threshold has not been set.
        if fail_threshold != "off":

            # Save a dictionary of what error codes to return.
            fail_codes = {
                "critical": 5,
                "high": 4,
                "medium": 3,
                "low": 2,
                "informational": 1
            }

            fail_threshold_value = fail_codes[fail_threshold]
            self.output_wrapper.set_title(
                "fail_threshold set to: " + str(fail_threshold_value))

            # Create a list to hold any failing issues
            fail_issues = []

            # For each issue, convert the severity into its fail_code
            # equivalent value.
            # If the value is greater than or equal to the fail_code
            # value of the set threshold, save it to a temporary array.
            for issue in self.issue_holder.get_issues():

                issue_dict = issue.getd()

                severity = issue_dict["severity"].lower()
                severity_value = fail_codes[severity]

                # Save this issue if it passes the threshold
                if severity_value >= fail_threshold_value:

                    self.output_wrapper.add(
                        "Found an issue with severity_value " + str(severity_value))

                    # mark the issue as failing
                    issue.set_fails(True)

                    # If we find an issue with a greater severity than what
                    # we've found so far, set error_code to its severity.
					# We'll return this at the end.
                    if severity_value > error_code:
                        error_code = severity_value

                    fail_issues.append(issue_dict)

            self.output_wrapper.flush(verbose=True)

            # Before we hard fail, explain why we failed and report the issues in shorthand form
            if error_code > 0:

                self.output_wrapper.set_title(
                    "Issue severity threshold met - failing build...")

                self.output_wrapper.add(
                    "At least one issue has been found with a severity that is greater than or equal to " + fail_threshold + "!")

                for issue in fail_issues:

                    reporting_tool = issue["tool_name"]
                    title = issue["title"].lower()
                    issue_severity = issue["severity"].lower()
                    description = issue["description"].split("\n")[0]
                    remediation = issue["recommendation"].split("\n")[0]
                    location = issue["location"]
                    uid = issue["uid"]

                    issue["fails"] = True

                    self.output_wrapper.add("")
                    self.output_wrapper.add("tool: " + reporting_tool)
                    self.output_wrapper.add("title: " + title)
                    self.output_wrapper.add("severity: " + issue_severity)
                    self.output_wrapper.add("description: " + description)
                    self.output_wrapper.add("recommendation: " + remediation)
                    self.output_wrapper.add("location: " + location)
                    self.output_wrapper.add("uid: " + uid)

                # for now, dump the array as a json blob into a file for parsing
                # by the parser lambda.

                self.output_wrapper.flush()

        # Return error_code as the error code :)
        return error_code

    def check_whitelists(self, config):
        """
        Loads the local whitelist from summit.yml and checks if any issues to be reported are within. If so, omit the issue from reporting (but report it in verbose mode).
        """

        self.output_wrapper.set_title(
            "Checking if any issues to report are whitelisted..")

        whitelisted_issues = config.get_whitelisted_issue_ids()

        # Go through all the issues
        tmp_issue_holder = self.issue_holder.get_issues()

        for whitelisted_id in whitelisted_issues:

            tmp_issue_holder = self.issue_holder.get_issues()

            for counter, issue in enumerate(tmp_issue_holder):
                issue = issue.getd()
                uid = issue["uid"]

                if uid in whitelisted_issues:
                    self.output_wrapper.add("Found and whitelisting " + uid + "...")
                    self.output_wrapper.add("- title: " + issue["title"])
                    self.output_wrapper.add("- location: " + issue["location"])
                    self.issue_holder.remove(counter)
                    break

        self.output_wrapper.add("[✓] Done!")
        self.output_wrapper.flush(verbose=True)

    def consume(self):
        """
        Absorbs a list of files and attempts to have each file parsed depending on the tool (and support)
        """

        for i_file in self.files:
            self.get_file_source(i_file)

    def __init__(self, output_wrapper, issue_holder, files):
        self.issue_holder = issue_holder
        self.output_wrapper = output_wrapper
        self.files = files

        self.consume()
