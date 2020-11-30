import hashlib
import pickle

class Issue:
    """
    Stores information on each parsed issue.
    """


    def set_fails(self, fail_bool):
        self.fails = fail_bool


    def __init__(
            self,
            issue_type,
            tool_name,
            title,
            description,
            location,
            recommendation,
            raw_output,
            severity,
            cve_value,
            custom
        ):
        """
        Instantiator of Issue objects.
        Currently only used to set the instance variables.
        """

        self.issue_type = issue_type
        self.tool_name = tool_name
        self.title = title
        self.description = description
        self.location = location
        self.recommendation = recommendation
        self.raw_output = raw_output
        self.severity = severity.lower()
        self.cve_value = cve_value
        self.custom = custom

        self.fails = False

        # Create a hash of the object as it is - we will use this to unique
        # identify it in case we need to allowlist it
        if tool_name == "gitleaks" or tool_name == "gosec": # The location of gitleaks issues is very dynamic so we need another factor
            self.hash = hashlib.sha256(f'{self.description}:{self.custom["file_location"]}'.encode('utf-8')).hexdigest()
        else:
            self.hash = hashlib.sha256(f"{self.description}:{self.location}".encode('utf-8')).hexdigest()


    def dictionary(self):
        """
        Returns a dictionary containing an issue's fieldnames and their values.
        """

        return {
            "issue_type": self.issue_type,
            "tool_name": self.tool_name,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "cve_value": self.cve_value,
            "location": self.location,
            "recommendation": self.recommendation,
            "raw_output": self.raw_output,
            "uid": self.hash,
            "fails": self.fails
        }


fieldnames = [
    "issue_type",
    "tool_name",
    "title",
    "severity",
    "description",
    "cve_value",
    "location",
    "recommendation",
    "raw_output",
    "uid",
    "fails"
]


def get_fieldnames():
    """
    Returns the list of keys each issue has.
    """

    return fieldnames