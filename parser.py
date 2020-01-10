
# -*- coding: utf-8 -*-

import json
import os
import constants
import re
from pprint import pprint

from bs4 import BeautifulSoup
from markdown import markdown


"""
This class deals with the reading and mapping of output from each security tool
into a common issue reporting format.

Each supported tool has an associated method that starts with parse_, i.e. 
"""
class Parser:


	parsed_tools = {
		"Snyk [Node]": "snyk_node"
	}


	def __init__(self):
		self.reporter = ""


	# """
	# Method that reads Anchore tool output and reports container findings to Reporter.
	# """
	# def parse_anchore(self, i_file):
	# 	a_output = json.load(i_file)
	# 	# Anchore outputs various information to multiple files,
	# 	# but we currently only care about the file containing identified vulnerabilities.
	# 	if "_latest-vuln" in i_file.name:
	# 		for vulnerability in a_output["vulnerabilities"]:
	# 		 	self.reporter.add_finding(
	# 				report_type="container_images",
	# 				tool="Anchore",
	# 				name="[" + vulnerability["severity"] + "] - " + vulnerability["vuln"],
	# 				description="A container package was identified as outdated and vulnerable.",
	# 				location="Package: " + vulnerability["package"],
	# 				raw_output=vulnerability,
	# 				i_file=i_file
	# 			)

	# """
	# Method that parses audit-ci output for packages using npm, forwarding vulnerable node dependency issues to Reporter.
	# """
	# def parse_audit_ci_npm(self, i_file):
	# 	report_type = "dependencies"
	# 	tool = "audit-ci [Node] [npm]"
	# 	# Some audit-ci runs do not generate output, let alone valid JSON
	# 	# To catch these we try to run json.load to parse the JSON.
	# 	# If the JSON is not well formed, then chances are there's no vulns.
	# 	# We'll inform the user, and carry on. It's okay.
	# 	# If we fail to parse then we can just grab the artifact from CircleCI and manually parse it.
	# 	try:
	# 		ac_output = json.load(i_file)
			
	# 		# Audit-CI output has a dictionary of advisories, with each key being the advisor number
	# 		# (similar to a CVE) and the value being another dictionary with further info.
	# 		# We may have to go recursive.
	# 		for advisory_number, advisory_info in ac_output["advisories"].items():

	# 			name = advisory_info["title"]

	# 			# If the issue has a severity prepend it to the issue name/title
	# 			if advisory_info["severity"]:
	# 				name = "[" + advisory_info["severity"].capitalize() + "] " + name

	# 			# Check if there's a CVE associated, in which case add this to the issue title
	# 			if advisory_info["cves"]:
	# 				name = "[" + ", ".join(advisory_info["cves"]) + "] " + name

	# 			# Description example: "123: This is the vuln issue. This is the vuln recommendation."
	# 			description = str(advisory_number) + ": " + advisory_info["overview"].rstrip() + " " + advisory_info["recommendation"].replace("\n", " ")

	# 			# Location example: "foobar 1.2.3 (foo>bar>foobar, bar>foo>foobar)"
	# 			location = "Package: " + advisory_info["module_name"] + " " + advisory_info["findings"][0]["version"] + " (" + ", ".join(advisory_info["findings"][0]["paths"]) + ")"

	# 			self.reporter.add_finding(
	# 				report_type=report_type,
	# 				tool=tool,
	# 				name=name,
	# 				description=description,
	# 				location=location,
	# 				raw_output=advisory_info,
	# 				i_file=i_file
	# 			)

	# 	except ValueError:
	# 		print("- Unable to parse JSON from " + os.path.basename(i_file.name) + "; skipping.")
		
	# 	print("- [✓] Done!")


	# """
	# Method that parses audit-ci output for packages using Yarn, forwarding vulnerable node dependency issues to Reporter.

	# audit-ci's parsing of Yarn packages is hella silly in my opinion.
	# It will output a JSON object for each vulnerability it finds, but does not bunch them together into an array
	# so that json.load() will not accept it. You can't slice the file to get each JSON body either as they are
	# prettified (so not single lined) and of different line lengths; ugh.
	# """
	# def parse_audit_ci_yarn(self, i_file):
	# 	report_type = "dependencies"
	# 	tool = "audit-ci [Node] [Yarn]"
		
	# 	formatted = []

	# 	# I'm going to try to fix the file first, by looking for closing brackets without whitespace before them (i.e. the last
	# 	# bracket of an object), and adding a comma to these (bar the last object, of course.)
	# 	# Afterwards, I will add opening and closing square brackets to the entire file to convert it into an array of JSON
	# 	# objects; json.load should be happy then.
	# 	lines = i_file.readlines()
	# 	for line in lines:
	# 		line = line.rstrip()
	# 		if line[0] != " " and line[-1] == "}":
	# 			formatted.append(line.rstrip() + ",")
	# 		else: 
	# 			formatted.append(line.rstrip())

	# 	# Get the first element and add an open square bracket to the beginning.
	# 	formatted[0] = "[" + formatted[0]
	# 	# Get the last element, remove the comma and replace it with a closed square bracket.
	# 	formatted[-1] = formatted[-1].replace(",", "]")

	# 	# Now we have to save the formatted array to a temporary file. 
	# 	import uuid
	# 	name = str(uuid.uuid4())
	# 	full_location = "/tmp/" + name
	# 	with open(full_location, 'w') as f:
	# 		f.write("\n".join(formatted))

	# 	# Using the temporary file, we can actually do the original parsing.
	# 	with open(full_location, 'r') as f:
	# 		try:
	# 			issues = json.load(f)
	# 			# Iterate through the individual issue objects, aside from the last objects (because it's just a
	# 			# summary count of the previous issues)
	# 			for issue in issues[:-1]:
	# 				advisory = issue['data']['advisory']

	# 				# resolution = issue['data']['resolution']
	# 				# pprint(resolution)

	# 				self.reporter.add_finding(
	# 					report_type=report_type,
	# 					tool=tool,
	# 					name="[" + advisory["severity"].capitalize() + "] " + advisory["title"],
	# 					description=advisory["overview"],
	# 					recommendation=advisory["recommendation"],
	# 					location="Package: " + "\n".join(advisory["findings"][0]["paths"]),
	# 					raw_output=advisory,
	# 					i_file=i_file
	# 				)

	# 		except ValueError:
	# 			print("- Unable to parse JSON from " + os.path.basename(i_file.name) + "; skipping.")

	# 	# Don't forget to delete the temporarily created file!
	# 	os.remove(full_location)

	# 	print("- [✓] Done!")


	# """
	# Method that parses detectsecrets output and forwards any potential credentials to Reporter.
	# """
	# def parse_detectsecrets(self, i_file):
	# 	ds_output = json.load(i_file)

	# 	for name, information in ds_output["results"].items():
	# 		self.reporter.add_finding(
	# 			report_type="secrets",
	# 			tool="detect-secrets",
	# 			name=information[0]["type"],
	# 			description="Potential credential found. Please check the reported file.",
	# 			location=str(name) + ", line " + str(information[0]["line_number"]),
	# 			raw_output=str(name) + ": " + str(information),
	# 			i_file=i_file
	# 		)


	# """
	# Method that parses DumpsterDiver output and forwards any potential credentials to Reporter.
	# """
	# def parse_dumpsterdiver(self, i_file):
	# 	dd_output = json.load(i_file) 

	# 	# If the JSON is an empty list, then there are no findings.
	# 	if len(dd_output) != 0:

	# 		# The loaded JSON is a list of findings.
	# 		for finding in dd_output:

	# 			# Check if a rule was triggered
	# 			if "Advanced rule" in finding["Finding"]:
	# 				# name = "DumpsterDiver Rule Triggered"
	# 				description = "A DumpsterDiver rule was triggered. Please check the raw output for further information."
	# 			else:
	# 				description = "Potential credential found: " + finding["Details"]["String"]

	# 			# Save finding, ready for reporting
	# 			self.reporter.add_finding(
	# 				report_type="secrets",
	# 				tool="DumpsterDiver",
	# 				name=finding["Finding"],
	# 				description=description,
	# 				location=finding["File"],
	# 				raw_output=finding,
	# 				i_file=i_file
	# 			)

	# 	else:
	# 		# Move on.
	# 		print("- [x] No output found in file; skipping.")


	"""
	Looks for the upgrade solutions proposed by Snyk so that a single recommendation/list of things to upgrade can be passed to a team. 
	
	In most cases this is better than assigning n*N issues to a team; just assign the single issue with all the fixes detailed.
	"""
	def snyk_node_report_upgrades(self, snyk_json_object, ifile_name):

		issue_type = "dependencies"
		tool_name = "snyk_node"
		title = "Overall Use of Outdated Node Dependencies"

		description = """The project in scope made use of outdated Node dependencies, which were susceptible to known vulnerabilities.\n\nPlease note: each dependency in the \"Location\" column has been individually reported as well for\ntracking purposes - this specific issue has been reported to identify and detail the path of least resistence when updating\ndependencies, to cover/mitigate the most vulnerabilities at the same time.
		""" 

		recommendation = """Upgrade all of the packages mentioned in the \"Location\" column to AT LEAST the version mentioned.\n\nWhere possible, update dependencies to their latest stable versions to make use of all possible\nsecurity patches and updates, but please double-check that updating does not break business-critical features before\ndoing so.
		"""

		# Disclose the project name first, then create some space to insert the upgrade paths below.
		location = snyk_json_object["projectName"] + "\n\n"

		upgrade_paths = snyk_json_object["remediation"]["upgrade"]

		for dependency_name, upgrade_details in upgrade_paths.items():

			# The values are in the form package@semver, so lets split via the @ and grab the dependency name.
			dependency_name = dependency_name.split("@")[0]

			# dependency_name actually has the used version attached (rather than the version we should be updating to), so we'll have to jump in its dict value and obtain the version to upgrade to.
			dependency_min_version = upgrade_details["upgradeTo"].split("@")[1]

			# add it to the location column as a dep that should be updated
			location += "> Update " + dependency_name + " to at least version " + dependency_min_version + "\n"

		self.reporter.add(
			issue_type,
			tool_name,
			title,
			description,
			location,
			recommendation, 
			ifile_name
		)

	"""
	Parses output generated by the Snyk CircleCI orb when scanning Node projects.
	"""
	def snyk_node(self, i_file):

		issue_type = "dependencies"
		tool_name = "snyk_node"
		ifile_name = i_file.name

		# # setting empty vars in case they aren't populated later down the line
		# cve_value = ""

		# Load the file into a blob
		i_file_json_object = json.load(i_file)

		# The rest of the method will individually report each bad dependency, but for brevity what we would do is report an issue that reports outdated dependencies as a whole along with their upgrade paths. :)
		self.snyk_node_report_upgrades(i_file_json_object, ifile_name)

		vulnerabilities = i_file_json_object["vulnerabilities"]
		print("- " + str(len(vulnerabilities)) + " vulnerablities found by " + tool_name + "!")

		for vulnerability in vulnerabilities:
			raw_output = vulnerability
			title = vulnerability["title"]
			severity = vulnerability["severity"]

			# Both the description and recommendation are shoved into the same key by Snyk, so we have to split them.
			# Also, Snyk dumps the output pre-formatted so we've gotta deal with this to get raw sentences we can deal with.
			snyk_description = vulnerability["description"]

			# Get rid of the Markdown and odd escaped characters.
			# BS4 is built for this, so lets not re-invent the wheel again.
			sd_html = markdown(snyk_description)
			sd_text = "".join(BeautifulSoup(sd_html, features="html.parser").findAll(text=True))

			# Get rid of all remaining new lines.
			description = sd_text.replace("\n", " ")

			# We have to remove the "Overview" heading from the description as we're using the "Description" header
			d_delim_start = "Overview "
			description = description[
				len(d_delim_start) :
			]

			# now we need to return the first two sentences of the description only. split the description into individual sentences using a regex, then join the first two elements.
			description = re.split(r'\. ', description)
			description = ". ".join(description[:2]) + '.'

			r_delim_start = "Remediation\n"
			r_delim_end = "References"
			recommendation = sd_text[
				sd_text.index(r_delim_start) + len(r_delim_start) : sd_text.index(r_delim_end)
			]
			recommendation = sd_text[sd_text.index("Remediation\n") + len("Remediation\n"):sd_text.index("\nReferences")]

			if "Otherwise, " in recommendation:
				recommendation = recommendation.split("Otherwise, ")[1]

			# Okay, lets find out which exact dependency is vulnerable by merging a specific list together
			location = " > ".join(vulnerability["from"])

			# Set cve_value to be equal to the CVE associated with the issue, but only if there is one.
			if vulnerability["identifiers"]["CVE"]:
				cve_value = vulnerability["identifiers"]["CVE"][0]

			# print("Title: " + title)
			# print("Severity: " + severity)
			# print("Description: " + description)
			# print("Location: " + location)
			# print("Recommendation: " + recommendation)
			# print("CVE: " + cve_value)
			# print("Affects: ")
			# print("-")

			self.reporter.add(
				issue_type,
				tool_name,
				vulnerability["packageName"] + " - " + title,
				description,
				location,
				recommendation,
				raw_output,
				ifile_name,
				severity = severity,
				cve_value = cve_value
			)


	"""
	This method iterates through a dictionary of tools that can be parse and compares its associated filename pattern with the file currently being processed.
	"""
	def find_output_file_source(self, i_file):
		# Get the tool name ("Snyk [Node]" for example) and its associated matching filename ("snyk_node"), both from parsed_tools in KV format
		for toolname, filename_pattern in self.parsed_tools.items():
			# Alright, we've found a file from a tool that we support
			if filename_pattern in i_file.name:
				# Lets obtain a link to the correct tool parser we'll be using. Thanks getattr, you're the best!
				print("- Tool identified: " + toolname)
				# We could squash the below into one line but it's more confusing to understand if you don't know getattr.
				file_parser_method = getattr(self, filename_pattern)
				file_parser_method(i_file)


	"""
	Absorbs a list of files (and a reporter object) and attempts to have each file parsed depending on the tool (and support)
	"""
	def consume(self, files, reporter):

		# Set the output folder variable in case we need to save parsed output
		self.reporter = reporter

		for i_file in files:
			print(">" * constants.SEPARATOR_LENGTH)
			print("Parsing: " + os.path.basename(i_file.name))
			print("-" * constants.SEPARATOR_LENGTH)

			self.find_output_file_source(i_file)

			print("<" * constants.SEPARATOR_LENGTH + "\n")


