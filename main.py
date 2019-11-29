#!/usr/bin/env python3

import argparse
import os
import traceback

from parser import Parser
from reporter import Reporter
from pathlib import Path

if __name__ == "__main__":
	print("\nCircleCI Security Output Parser (CSOP) - Hi there!")
	print("To be used with https://https://circleci.com/orbs/registry/orb/salidas/security")

	parser = argparse.ArgumentParser()
	parser.add_argument(
		"-i",
		"--input",
		help="The directory to load security tool output from"
		)
	parser.add_argument(
		"-o",
		"--output",
		help="The directory to store the parsed data to",
		default="."
		)

	arguments = parser.parse_args()

	# Create variables to store where to load and save files from/to.
	i_folder = arguments.input
	o_folder = arguments.output

	# Create a blank list to keep track of any security tool output
	files = []

	# Get the absolute path for the input folder
	i_folder = os.path.abspath(i_folder)
	print("\nLoading from: " + i_folder)

	# Get the absolute path for the output folder
	o_folder = os.path.abspath(o_folder)

	# Create open file objects for all JSON files in the input folder
	# and store them in the files list object
	for fname in Path(i_folder).glob("**/results_*.json"):
		i_file = open(fname, "r")
		files.append(i_file)

	# Check if we were able to load any files
	if len(files) != 0:

		# Found some files! Lets list them.
		if len(files) == 1:
			print("1 file was found!")
		else:
			print(str(len(files)) + " files were found!")
		for f_object in files:
			print("- " + os.path.basename(f_object.name))
		print()
		try:
			# Create Reporter and Parser objects then pass the list of file
			# objects (and the parser) to the parser.
			reporter = Reporter(o_folder)
			parser = Parser()
			# try:
			# 	parser.identify(files, reporter)
			# except Exception as ex:
			# 	print("An error occurred!")
			# 	print(ex)
			parser.identify(files, reporter)
			reporter.create_report()
		# Be nice, and if something breaks return the stack trace for debugging.
		except Exception as ex:
			print(">" * 10 + "\nAN UNEXPECTED ERROR HAS OCCURRED:\n" + "-" * 10)
			print(traceback.print_tb(ex.__traceback__))
	else:
		# We didn't find any files; odd.
		print("No supported files were found! Did you target the right directory?")
