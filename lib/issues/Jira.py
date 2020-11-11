import os

from jira import JIRA
from jira.exceptions import JIRAError

class Jira:

    def __connect(self):
        try:
            self.j = JIRA(
                    self.m.jira_server,
                    basic_auth = (
                        self.m.jira_username,
                        self.m.jira_api_token
                    )
                )
            return True
        except JIRAError as e:
            self.l.error("An error occurred when trying to connect to the JIRA instance.")
            if e.status_code == 401:
                self.l.error("We received a 401. Are your credentials correct?")
            else:
                self.l.error("We're not sure what happened, so here's the stack:\n-----\n")
                print(e.text)
                print("-----")
        return False


    def __init__(self, logger, metadata, issue_holder):
        self.l = logger
        self.m = metadata
        self.issue_holder = issue_holder
        self.jira_config = self.m.jira_config


    def check(self, issues):
        print()

        sorted = False
        sorted_issues = []

        if self.__connect():
            self.l.info("Connected to JIRA")
            self.l.info("Checking JIRA for issues matching raised tickets")
            
            # Firstly, look for the ticket for the repository
            search_string = f'Summary ~ "{self.m.repository}" '
            search_string += f'AND project = "{self.jira_config["project"]}"'

            repository_tickets = self.j.search_issues(search_string, validate_query=True)
            if len(repository_tickets) >= 1:
                repository = repository_tickets[0]
                self.l.info(f"Found repository ticket: {repository.key} - {repository.fields.summary}")
                
                self.l.debug("Checking the repository's subtasks for matching tickets")

                for subtask in repository.fields.subtasks:
                    subtask_issue = self.j.issue(subtask.key)
                    subtask_hash = subtask_issue.raw["fields"][self.jira_config["hash_field"]]

                    for issue in issues:
                        issue_hash = issue["uid"]

                        if subtask_hash == issue_hash:
                            self.l.info(f"Found ticket {subtask.key} for hash ending in {issue_hash[-5:]}")
                            subtask_status = str(subtask_issue.fields.status)
                            # self.l.debug(f"> Ticket has a status of {subtask_status}")
                            self.l.info(f'> Ticket has a status of "{subtask_status.lower()}"')

                            # If the status is not accepted, we'll add it to a new list.
                            if subtask_status.lower() not in self.jira_config["accepted_statuses"]:
                                sorted_issues.append(issue)
                                # self.l.info(">>> ")
                            # If the status is accepted, we'll log this and do nothing with it.
                            # The issue will not be in list of issues to report.
                            else:
                                self.l.info(">>> This status is acceptable - omitting from report")
                sorted = True

            else:
                self.l.error("Repository ticket not found!")

        if not sorted:
            sorted_issues = issues 
        
        print()
        return sorted_issues
