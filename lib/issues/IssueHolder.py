import hashlib
import json

from lib.issues.Issue import Issue

class IssueHolder:
    """
    Simple class just used to retain information on the issues found during this parser's run.
    """

    def __init__(self, logger):
        """
        Simple init - creates the instance's list object.
        """

        self.l = logger
        self.findings_list = list()


    def deduplicate(self):
        """
        Goes through the list and removes and duplicate issues.
        In the process, it also creates a unique hash for each issue.
        """

        self.l.info("Deduplicating...")

        # Create an empty list that will store calculated hashes.
        issue_hash_oracle = []

        # Create an empty list that will contain the unique issues.
        deduplicated_findings = []

        # Iterate though a deep copy of the current issues we have
        for issue in self.get_issues():

            # Get the contents of the issue in dictionary format
            issue = issue.dictionary()

            # issue_hash = self.create_hash(issue)

            # uid = hash
            if issue["uid"] not in issue_hash_oracle:
                issue_hash_oracle.append(issue["uid"])
                deduplicated_findings.append(issue)

        # The description and location of each issue is merged together and
        # hashed - if this hash has not been dealt with (this parsing round)
        # before then we'll accept it, otherwise ignore it.

        self.l.debug(f"Array size: {self.size()}")
        self.l.info(f"Array size after deduplication: {len(deduplicated_findings)}")

        return deduplicated_findings


    def remove(self, index):
        """
        Removes an issue from the list depending on its index.
        """
        del self.findings_list[index]


    def add(
        self,
        issue_type,
        tool_name,
        title,
        description,
        location,
        recommendation,
        raw_output = "n/a",
        severity = "low",
        cve_value = "n/a",
        custom = {}
    ):
        """
        Inserts a new issue to the list; the parameters force a reporting standard to be followed (i.e. each must have the first six parameters as "headings" in a report)
        """

        self.findings_list.append(
            Issue(
                issue_type,
                tool_name,
                title,
                description,
                location,
                recommendation,
                raw_output=raw_output,
                severity=severity,
                cve_value=cve_value,
                custom=custom
            )
        )


    def get_issues(self):
        """
        Returns the current list of issues.
        """

        return self.findings_list


    def get_issuesa(self):
        """
        Returns the list of current issues albeit in readable dictionary
        format for each issue
        """

        array = []

        for issue in self.get_issues():
            array.append(issue.dictionary())

        return array


    def size(self):
        """
        Returns the size of the current list of issues.
        """

        return len(self.findings_list)