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
            ifile_name="",
            raw_output="n/a",
            severity="",
            cve_value="n/a",
            fails=False
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
        self.ifile_name = ifile_name
        self.raw_output = raw_output
        if severity == "":
            self.severity = "low"
        else:
            self.severity = severity
        self.cve_value = cve_value
        self.fails = fails

        # Create a hash of the object as it is - we will use this to unique
        # identify it in case we need to allowlist it
        # self.hash = hashlib.sha256(pickle.dumps(self)).hexdigest()
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