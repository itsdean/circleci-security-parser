import logging
import os
import sys
import yaml

from os import path
from ..output.Logger import Logger

class ConfigHandler:


    def __init__(self, logger, filename):

        self.l = logger

        # Define the various configuration fields
        # By default, parser builds fail if an issue with severity high or
        # above was found.
        self.fail_threshold = "high"
        self.fail_branches = []
        self.jira = False
        self.jira_config = {}
        self.allowlisted_issues = []
        self.gitleaks = {}
        self.upload_to_aws = False

        # Load the configuration file
        self.load(filename)


    def parse(self, yaml_object):
        """
        Obtains the various fields from the yaml file. 
        """

        if "fail_threshold" in yaml_object:
            self.fail_threshold = yaml_object["fail_threshold"]

            if type(self.fail_threshold) is bool:
                self.l.error("fail_threshold is a bool, did you use double quotes when defining fail_threshold in the .yml file?")
                sys.exit(-1)

            if "fail_branches" in yaml_object:
                self.fail_branches = yaml_object["fail_branches"]
        
        self.l.info(f"Fail threshold: {self.fail_threshold.capitalize()}")

        if "allowlist" in yaml_object:
            self.allowlisted_issues = yaml_object["allowlist"]
            if "ids" in self.allowlisted_issues and self.allowlisted_issues['ids'] is not None:
                self.l.info(f"Loaded {len(self.allowlisted_issues['ids'])} allowed ID(s) from config file")
            if "paths" in self.allowlisted_issues and self.allowlisted_issues['paths'] is not None:
                self.l.info(f"Loaded {len(self.allowlisted_issues['paths'])} allowed path(s) from config file")

        if "aws" in yaml_object:
            self.upload_to_aws = yaml_object["aws"]

        if "jira" in yaml_object:
            self.jira = yaml_object["jira"]

        if "jira_config" in yaml_object:
            self.jira_config = yaml_object["jira_config"] 

        if "gitleaks" in yaml_object:
            self.gitleaks = yaml_object["gitleaks"]


    def load(self, filename):
        """
        Loads the actual file into a structure known to pyyaml.
        """

        # resolve the path relative to the current location
        filename = os.path.relpath(filename)

        self.l.info(f"Loading configuration from {filename}")

        if path.exists(filename):

            with open(filename) as config_file:
                # self.l.debug(f"{filename} found")

                yaml_object = yaml.load(config_file, Loader=yaml.FullLoader)
                if yaml_object is not None:
                    self.parse(yaml_object)
                else:
                    self.l.warning("yaml_object is None - skipping YAML parse stage")

        else:
            self.l.warning(f"{filename} not found - skipping YAML parse stage")

        print()
