
# -*- coding: utf-8 -*-

import json
import os

"""

FYI

csv format

report_type - secrets, container, code, etc.
tool - tool used
name - issue that tool reported + rating where available
description - issue description if availabke?
location - location of finding
raw_output - raw finding output for triaging, along with filename

"""
class Parser:

	accepted_tools = {
		"DumpsterDiver": {
			"match": "dumpsterdiver",
		} ,
		"detect-secrets": {
			"match": "detect-secrets",
		}
	}


	def __init__(self):
		self.reporter = ""


	def parse_detectsecrets(self, i_file):
		ds_output = json.load(i_file)
		# print(ds_output)

		for name, information in ds_output["results"].items():
			# print(name, information)
			self.reporter.add_finding(
				report_type="secrets",
				tool="detect-secrets",
				name=information[0]["type"],
				description="Potential credential found. Please check the reported file.",
				location=str(name) + ", line " + str(information[0]["line_number"]),
				raw_output=str(name) + ": " + str(information),
				i_file=i_file
			)


	def parse_dumpsterdiver(self, i_file):
		dd_output = json.load(i_file) 

		# If the JSON is an empty list, then there are no findings.
		if len(dd_output) != 0:

			# The loaded JSON is a list of findings.
			for finding in dd_output:

				# Check if a rule was triggered
				if "Advanced rule" in finding["Finding"]:
					name = "DumpsterDiver Rule Triggered"
					description = "A DumpsterDiver rule was triggered. Please check the raw output for further information."
				else:
					description = "Potential credential found: " + finding["Details"]["String"]

				# Save finding, ready for reporting
				self.reporter.add_finding(
					report_type="secrets",
					tool="DumpsterDiver",
					name=finding["Finding"],
					description=description,
					location=finding["File"],
					raw_output=finding,
					i_file=i_file
				)

		else:
			# Move on.
			print("No output found in file - ignoring.")


	def parse(self, i_file, tool_name):
		if tool_name == "DumpsterDiver":
			self.parse_dumpsterdiver(i_file)
		elif tool_name == "detect-secrets":
			self.parse_detectsecrets(i_file)


	def detect(self, i_file):
		for tool_name, options in self.accepted_tools.items():
			if options["match"] in i_file.name:
				print("Tool identified: " + tool_name)
				self.parse(i_file, tool_name)


	def identify(self, files, reporter):

		# Set the output folder variable in case we need to save parsed output
		self.reporter = reporter

		for i_file in files:

			print("Parsing: " + os.path.basename(i_file.name))
			print("-" * 50)
			self.detect(i_file)
			print()


