import hashlib
import json

class IssueHolder:
    """
    Simple class just used to retain information on the issues found during this parser's run.
    """

    def __init__(self, output_wrapper):
        """
        Simple init - creates the instance's list object.
        """

        self.output_wrapper = output_wrapper

        # self.output_wrapper.set_title("Deduplicating...")
        self.findings_list = []


    def create_hash(self, issue):
        """
        Creates a unqiue hash using fields from the issue.
        This hash will be used for deduplication and 
        """

        description = issue["description"].encode("utf-8")
        location = issue["location"].encode("utf-8")

        # issue = json.dumps(issue, sort_keys=True, default=str)

        issue_hash = hashlib.sha256(
            description + b":" + location
        ).hexdigest()

        # self.output_wrapper.add("Generated hash: " + issue_hash)
        
        return issue_hash


    def deduplicate(self):
        """
        Goes through the list and removes and duplicate issues.
        In the process, it also creates a unique hash for each issue.
        """

        self.output_wrapper.set_title("Deduplicating...")

        # Create an empty list that will store calculated hashes.
        issue_hash_oracle = []

        # Create an empty list that will contain the unique issues.
        deduplicated_findings = []

        # Iterate though a deep copy of the current issues we have
        for element in list(self.get_issues()):
 
            # Get the contents of the issue in dictionary format
            issue = element.get()

            issue_hash = self.create_hash(issue)

            if issue_hash not in issue_hash_oracle:

                issue_hash_oracle.append(issue_hash)
                deduplicated_findings.append(issue)

            # issue_hash = create_hash()

        # The description and location of each issue is merged together and
        # hashed - if this hash has not been dealt with (this parsing round)
        # before then we'll accept it, otherwise ignore it.

        self.output_wrapper.add("- Array size: " + str(self.size()))
        self.output_wrapper.add("- Array size after deduplication: " + str(len(deduplicated_findings)))

        return deduplicated_findings


    def add(self, issue):
        """
        Adds a new issue to the list of issues.
        """

        self.findings_list.append(issue)


    def get_issues(self):
        """
        Returns the current list of issues.
        """

        return self.findings_list


    def size(self):
        """
        Returns the size of the current list of issues.
        """

        return len(self.findings_list)