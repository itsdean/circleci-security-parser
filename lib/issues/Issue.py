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

def get_fieldnames():
    return fieldnames


class Issue:


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
            severity="n/a",
            cve_value="n/a"
        ):

        self.issue_type = issue_type
        self.tool_name = tool_name
        self.title = title
        self.description = description
        self.location = location
        self.recommendation = recommendation
        self.ifile_name = ifile_name
        self.raw_output = raw_output
        self.severity = severity
        self.cve_value = cve_value


    def get(self):
        return {
            "issue_type": self.issue_type,
            "tool_name": self.tool_name,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "cve_value": self.cve_value,
            "location": self.location,
            "recommendation": self.recommendation,
            "raw_output": self.raw_output
        }
