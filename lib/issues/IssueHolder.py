class IssueHolder:
    """
    Simple class just used to retain information on the issues found during this parser's run.
    """

    def __init__(self):
        """
        Simple init - creates the instance's list object.
        """

        self.findings_list = []


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