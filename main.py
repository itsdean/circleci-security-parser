#!/usr/bin/env python3

import argparse
import os

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

	files = []

	# Get the absolute path for the input folder
	i_folder = os.path.abspath(i_folder)
	print("\nLoading from: " + i_folder)

	# Get the absolute path for the output folder
	o_folder = os.path.abspath(o_folder)
	print("Saving to: " + o_folder + "\n")

	for fname in Path(i_folder).glob("**/*.json"):
		i_file = open(fname, "r")
		files.append(i_file)

	# Check if we were able to load any files
	if len(files) != 0:

		print(str(len(files)) + " files were found!\n")

		reporter = Reporter(o_folder)
		parser = Parser()
		try:
			parser.identify(files, reporter)
		except Exception as ex:
			print("An error occurred!")
			print(ex)
		reporter.create_report()
	else:
		print("No supported files were found! Did you target the right directory?")