class IssueHolder:

    def __init__(self):
        self.findings_list = []


    def add(self, issue):
        self.findings_list.append(issue)


    def get_issues(self):
        return self.findings_list


    def size(self):
        return len(self.findings_list)