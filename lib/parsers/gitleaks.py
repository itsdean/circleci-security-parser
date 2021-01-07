import json

from ..constants import an

MAX_LINE_LENGTH = 100

ISSUE_TYPE = "secrets"
TOOL_NAME = "gitleaks"

# Due to the potential risk of it being a real credential, we should always make these stand out.
SEVERITY = "medium"

RECOMMENDATION = """Please identify whether this finding is valid.
It is recommended to make use of secrets management tools/functionality such as
AWS Secrets Manager to retrieve sensitive values or credentials when required, rather than hardcoding contents.
"""

def parse_individual(gitleaks_issues, issue_holder, logger, metadata):
    """
    Goes through gitleaks --verbose output, combines them into a proper JSON
    object, then passes each reported issue to Reporter.
    """

    for issue in gitleaks_issues:

        custom = {
            "type": "single",
            "filename": issue["file"],
            "line": issue["lineNumber"]
        }

        filename = issue["file"].rsplit("/")[-1]

        title = f'{issue["rule"]} found at \"{filename}\"'
        description = f'A potential credential was found in a file. The gitleaks rule that triggered was \"{issue["rule"].lower()}\".'

        # Create the file location for the repository URL
        location = metadata.repository_url
        if "/" in issue["file"]:
            location += f'/blob/{issue["commit"]}/{issue["file"]}'
            if issue["lineNumber"] > 0:
                location += f'#L{issue["lineNumber"]}'

        # Report the issue differently if the rule is for a file pattern
        if "Filename/path" in issue["offender"]:
            # description += f"\nThe file that triggered this rule was {}"
            description += f'\nThe file that triggered this rule was "{issue["file"]}"'
            description += "\nAs this was a filename/path rule that triggered, please search the repository for matching files and confirm if they are valid."
            location = "N/A"

        # Otherwise we'll set the full file path, and report the line that triggered
        else:

            description += "\n\nThe offence can be found below:"

            # We might be reporting minified JS, so lets check
            offending_line = issue["line"]
            # If the line is too long, we'll just report the specific trigger
            if len(offending_line) > MAX_LINE_LENGTH:
                offending_line = issue["offender"]

            if metadata.jira:
                description += "\n{code}\n" + offending_line + "\n{code}"
            else:
                description += f'\n{offending_line}\n'

            # Create the file location for the repository URL
            location = metadata.repository_url
            location += f'/blob/{issue["commit"]}/{issue["file"]}'
            if issue["lineNumber"] > 0:
                location += f'#L{issue["lineNumber"]}'

        issue_holder.add(
            ISSUE_TYPE,
            TOOL_NAME,
            title,
            description,
            location,
            RECOMMENDATION,
            severity = SEVERITY,
            raw_output = issue,
            custom = custom
        )

    logger.debug(f"> gitleaks: {len(gitleaks_issues)} issues reported\n")


def parse_multiple(gitleaks_issues, issue_holder, logger, metadata):

    files = {}

    # Merge issues together if they're from the same file
    for issue in gitleaks_issues:

        if issue["file"] not in files.keys():
            filename = issue["file"].rsplit("/")[-1]

            files[issue["file"]] = {
                "offences": [
                    {
                        "rule": issue["rule"],
                        "lineNumber": issue["lineNumber"],
                        "line": issue["line"],
                        "offender":  issue["offender"],
                    }
                ],
                "title": f"Potential credentials found at \"{filename}\"",
                "commit": issue["commit"],
                "path": issue["file"],
                "repository_path_known": False,
                "repository_path": "N/A",
                "description": f'Potential credentials were found in a file.'
            }
        else:
            files[issue["file"]]["offences"].append(
                {
                    "rule": issue["rule"],
                    "lineNumber": issue["lineNumber"],
                    "line": issue["line"],
                    "offender":  issue["offender"]
                }
            )

        # Deduce the file path (and tailor the description) if it's not a whole-file rule
        if "Filename/path" not in issue["offender"]:

            # Get the repository file URL
            path = metadata.repository_url
            path += f"/blob/{files[issue['file']]['commit']}/{issue['file']}"

            # Add an atomic line to the description and save the file URL
            if not files[issue["file"]]["repository_path_known"]:
                files[issue["file"]]["description"] += "\n\nMatches for the following gitleaks rule(s) were found:"
                files[issue["file"]]["repository_path_known"] = True
                files[issue["file"]]["repository_path"] = path

            # Add an entry in the description for this offence
            files[issue["file"]]["description"] += f"\n{issue['rule']} at line {issue['lineNumber']}:\n- "
            if len(issue["line"]) > MAX_LINE_LENGTH:
                files[issue["file"]]["description"] += f"{issue['offender']}\n"
            else:
                files[issue["file"]]["description"] += f"{issue['line']}\n"

        # If it's a whole-file rule, tailor the description
        else:
            files[issue["file"]]["description"] += f"\nThe file that triggered this rule was \"{issue['file']}\""
            files[issue["file"]]["description"] += "\nAs this was a filename/path rule that triggered, please search the repository for matching files and confirm if they are valid."

    for offending_file in files.keys():

        custom = {
            "type": "multiple",
            "filepath": offending_file
        }

        path = files[offending_file]["path"]
        if files[offending_file]["repository_path"] is not "N/A":
            path = files[offending_file]["repository_path"]

        issue_holder.add(
            ISSUE_TYPE,
            TOOL_NAME,
            files[offending_file]["title"],
            files[offending_file]["description"],
            path,
            RECOMMENDATION,
            severity = SEVERITY,
            raw_output = files[offending_file],
            custom = custom
        )

    logger.debug(f"> gitleaks: {len(files)} issues reported\n")

def parse(gitleaks_file, issue_holder, logger, metadata):
    gitleaks_issues = json.load(gitleaks_file)

    if metadata.gitleaks and "individual" in metadata.gitleaks and metadata.gitleaks["individual"]:
        parse_individual(gitleaks_issues, issue_holder, logger, metadata)
    else:
        parse_multiple(gitleaks_issues, issue_holder, logger, metadata)