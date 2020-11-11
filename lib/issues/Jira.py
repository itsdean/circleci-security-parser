import os

from jira import JIRA
from jira.exceptions import JIRAError

class Jira:

    def connect(self):
        try:
            self.client = JIRA(
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


    def __init__(self, logger, metadata):
        self.l = logger
        self.m = metadata
        self.jira_config = self.m.jira_config

    def get_repository(self):
            search_string = f'Summary ~ "{self.m.repository}" '
            search_string += f'AND project = "{self.jira_config["project"]}"'

            repository_tickets = self.client.search_issues(search_string, validate_query=True)
            if len(repository_tickets) >= 1:
                repository = repository_tickets[0]
                return repository
            else:
                return None

    def get_subtasks(self, ticket_key):
        ticket = self.client.issue(ticket_key)
        if len(ticket.fields.subtasks) > 0:
            return ticket.fields.subtasks
        else:
            return None

