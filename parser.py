
# -*- coding: utf-8 -*-

import json
import os
import constants
import re

from pprint import pprint
from outputter import Outputter

class Parser:
	"""
	Redirects files to their respective parsers to be processed.
	"""

	parsed_tools = {
		"gosec": "gosec",
		"nancy": "nancy",
		"burrow": "burrow",
		"Snyk [Node]": "snyk_node",
	}


	def gosec(self, i_file):
		from lib import gosec
		gosec.parse(i_file, self.reporter)


	def nancy(self, i_file):
		from lib import nancy
		nancy.parse(i_file, self.reporter)


	def burrow(self, i_file):
		from lib import burrow
		burrow.parse(i_file, self.reporter)


	def snyk_node(self, i_file):
		from lib import snyk
		snyk.parse_node(i_file, self.reporter)


	def get_file_source(self, i_file):
		"""
		Iterates through a dictionary of tools that can be parsed and compares their associated filename patterns with the file currently being processed.
		"""

		# Get the tool name ("Snyk [Node]" for example) and its associated matching filename ("snyk_node"), both from parsed_tools in KV format
		for toolname, filename_pattern in self.parsed_tools.items():
			# Alright, we've found a file from a tool that we support
			if filename_pattern in i_file.name:
				# Lets obtain a link to the correct tool parser we'll be using. Thanks getattr, you're the best!
				print("- Tool identified: " + toolname)
				# We could squash the below into one line but it's more confusing to understand if you don't know getattr.
				file_parser_method = getattr(self, filename_pattern)
				file_parser_method(i_file)


	def consume(self, files, reporter):
		"""
		Absorbs a list of files (and a reporter object) and attempts to have each file parsed depending on the tool (and support)
		"""

		# Set the output folder variable in case we need to save parsed output
		self.reporter = reporter

		for i_file in files:
			print(">" * constants.SEPARATOR_LENGTH)
			print("Parsing: " + os.path.basename(i_file.name))
			print("-" * constants.SEPARATOR_LENGTH)

			self.get_file_source(i_file)

			print("<" * constants.SEPARATOR_LENGTH + "\n")


	def check_threshold(self, fail_threshold):
		"""
		Check if an issue severity threshold has been set and if so, return an error code equal to a map against the issues to be reported.

		The error code returned depends on the issue with the highest severity. 5 = critical, 4 = high, etc. 

		tl;dr if fail_threshold = "high", return 4 if we only find high issues, and return 5 if we find a critical. if don't find either, return 0.
		"""

		

		# Only go down this route if a threshold has not been set.
		if fail_threshold != "off":

			# Save a dictionary of what error codes to return.
			fail_codes = {
				"critical": 5,
				"high": 4,
				"medium": 3,
				"low": 2,
				"informational": 1
			}

			fail_threshold_value = fail_codes[fail_threshold]
			self.outputter.set_title("ftv: " + str(fail_threshold_value))

			# Create a list to hold any failing issues
			fail_issues = []

			# Stores the return value of the script
			error_code = 0

			# For each issue, convert the severity into its fail_code
			# equivalent value.
			# If the value is greater than or equal to the fail_code
			# value of the set threshold, save it to a temporary array.
			for issue in self.reporter.get():
				
				# pprint(issue)

				severity = issue["severity"].lower()
				severity_value = fail_codes[severity]
				self.outputter.add("found one with severity: " + severity + ", severity_value: " + str(severity_value))

				# Save this issue if it passes the threshold
				if severity_value >= fail_threshold_value:

					# If we find an issue with a greater severity than what 
					# we've found so far, set error_code to it. We'll return
					# this at the end.
					if severity_value > error_code:
						error_code = severity_value
						self.outputter.add("now returning error_code " + str(error_code))

					fail_issues.append(issue)

			# Print out each issue
			# pprint(fail_issues)

			self.outputter.flush()

			# Return error_code as the error code :)
			return error_code

	def __init__(self):
		self.outputter = Outputter()