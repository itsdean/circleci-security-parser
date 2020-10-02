
# -*- coding: utf-8 -*-

import json
import os
import re

from ..issues.IssueHolder import IssueHolder

class CoreParser:
    """
    Redirects files to their respective parsers to be processed.
    """

    parsable_tools = {
        "gosec": "gosec",
        "nancy": "nancy",
        "burrow": "burrow",
        "gitleaks": "gitleaks",
        "Snyk [Node]": "snyk_node",
        "insider": "insider",
        "shed": "shed",
        "trivy": "trivy"
    }

    def gosec(self, i_file):
        from lib.parsers import gosec
        gosec.parse(i_file, self.issue_holder, self.l)

    def nancy(self, i_file):
        from lib.parsers import nancy
        nancy.parse(i_file, self.issue_holder, self.l)

    def burrow(self, burrow_file):
        from lib.parsers import burrow
        burrow.parse(burrow_file, self.issue_holder, self.l)

    def gitleaks(self, gitleaks_file):
        from lib.parsers import gitleaks
        gitleaks.parse(gitleaks_file, self.issue_holder, self.l)

    def snyk_node(self, i_file):
        from lib.parsers import snyk
        snyk.parse_node(i_file, self.issue_holder, self.l)

    def insider(self, insider_file):
        from lib.parsers import insider
        insider.parse(insider_file, self.issue_holder, self.l)

    def shed(self, shed_file):
        from lib.parsers import shed
        shed.parse(shed_file, self.issue_holder, self.l)

    def trivy(self, trivy_file):
        from lib.parsers import trivy
        trivy.parse(trivy_file, self.issue_holder, self.l)

    def __parse(self, i_file):
        """
        Iterates through a dictionary of tools that can be parsed and compares their associated filename patterns with the file currently being processed.
        """

        self.l.info(f"Parsing {os.path.basename(i_file.name)}")

        # Get the tool name ("Snyk [Node]" for example) and its associated matching filename ("snyk_node"), both from parsed_tools in KV format
        for toolname, filename_pattern in self.parsable_tools.items():

            # Alright, we've found a file from a tool that we support
            if filename_pattern in i_file.name:

                # Lets obtain a link to the correct tool parser we'll be using. Thanks getattr,
                self.l.debug(f"> Tool identified: {toolname}")

                file_parser_method = getattr(self, filename_pattern)
                file_parser_method(i_file)

        # print()


    def parse(self, input_files):
        for input_file in input_files:
            self.__parse(input_file)
        # print()


    def check_threshold(self, fail_threshold):
        """
        Check if an issue severity threshold has been set and if so, return an error code equal to a map against the issues to be reported.

        The error code returned depends on the issue with the highest severity. 5 = critical, 4 = high, etc.

        tl;dr if fail_threshold = "high", return 4 if we only find high issues, and return 5 if we find a critical. if don't find either, return 0.
        """

        # Store the return value of the script
        exit_code = 0

        # For output cleanliness, only report a failure once
        fail_outputted = False

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

            # Create a list to hold any failing issues
            fail_issues = []

            # For each issue, convert the severity into its fail_code
            # equivalent value.
            # If the value is greater than or equal to the fail_code
            # value of the set threshold, save it to a temporary array.
            for issue in self.issue_holder.get_issues():

                issue_dict = issue.dictionary()

                severity = issue_dict["severity"].lower()
                severity_value = fail_codes[severity]

                # Save this issue if it passes the threshold
                if severity_value >= fail_threshold_value:

                    if not fail_outputted:
                        self.l.debug(f"Issue severity threshold met, found an issue with severity_value {severity_value}")
                        fail_outputted = True

                    # mark the issue as failing
                    # issue.set_fails(True)
                    issue.fails = True

                    # If we find an issue with a greater severity than what
                    # we've found so far, set error_code to its severity.
					# We'll return this at the end.
                    if severity_value > exit_code:
                        exit_code = severity_value

                    fail_issues.append(issue_dict)

            # Before we hard fail, explain why we failed and report the issues in shorthand form
            if exit_code > 0:

                self.l.warning(f"At least one issue has been found with a severity that is greater than or equal to {fail_threshold}!")

                for issue in fail_issues:

                    reporting_tool = issue["tool_name"]
                    title = issue["title"].lower()
                    issue_severity = issue["severity"].lower()
                    description = issue["description"].split("\n")[0]
                    remediation = issue["recommendation"].split(". ")[0] + "."
                    location = issue["location"]
                    uid = issue["uid"]

                    issue["fails"] = True

                    print("")
                    self.l.info(f"tool: {reporting_tool}")
                    self.l.info(f"title: {title}")
                    self.l.info(f"severity: {issue_severity}")
                    self.l.info(f"description: {description}")
                    self.l.info(f"recommendation: {remediation}")
                    self.l.info(f"location(s): {location}")
                    self.l.info(f"uid: {uid}\n")

        # Return error_code as the error code :)
        return exit_code

    def check_allowlists(self, allowlisted_issues):
        """
        Loads the local allowlist from summit.yml and checks if any issues to be reported are within. If so, omit the issue from reporting (but report it in verbose mode).
        """

        self.l.info("Checking if any issues or paths are allowlisted")

        # Go through a snapshot of the issues by making a duplicate list
        tmp_issue_holder = self.issue_holder.get_issues()

        removed_issues = 0

        # deal with ids
        if "ids" in allowlisted_issues:
            ids = allowlisted_issues["ids"]
            for allowlisted_id in ids:
                tmp_issue_holder = self.issue_holder.get_issues()

                for counter, issue in enumerate(tmp_issue_holder):
                    issue = issue.dictionary()

                    if issue["uid"] in allowlisted_issues:
                        self.l.debug(f"Found and allowing {issue['uid']}...")
                        self.l.debug(f"> title: {issue['title']}")
                        self.l.debug(f"> location(s):  {issue['location']}")
                        self.issue_holder.remove(counter)
                        removed_issues += 1
                        break

        # deal with paths
        if "paths" in allowlisted_issues:
            paths = allowlisted_issues["paths"]
            for path in paths:
                tmp_issue_holder = self.issue_holder.get_issues()
                for counter, issue in enumerate(tmp_issue_holder):
                    issue = issue.dictionary()
                    
                    if path in issue["location"]:
                        if self.l.verbose:
                            print()
                        self.l.debug(f"Issue found in an allowed path, omitting...")
                        self.l.debug(f"> title: {issue['title']}")
                        self.l.debug(f"> location(s):  {issue['location']}")
                        self.l.debug(f"> allowlist trigger: {path}")
                        self.issue_holder.remove(counter)
                        removed_issues += 1

        print()
        self.l.debug("Finished checking allowed issues")
        self.l.info(f"Number of allowed issues removed from report: {removed_issues}")
        print()


    def __init__(self, logger, issue_holder):
        self.l = logger
        self.issue_holder = issue_holder
