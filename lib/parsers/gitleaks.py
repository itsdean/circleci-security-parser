import json

from ..constants import an

MAX_LINE_LENGTH = 100

def parse(gitleaks_file, issue_holder, logger, metadata):
    """
    Goes through gitleaks --verbose output, combines them into a proper JSON
    object, then passes each reported issue to Reporter.
    """

    issue_type = "secrets"
    tool_name = "gitleaks"

    # Due to the potential risk of it being a real credential, we should always make these stand out.
    severity = "medium"

    recommendation = ""
    if metadata.jira:
        recommendation += "h4. Recommendation\n"
    recommendation += "Please identify whether this finding is valid.\nIt is recommended to make use of secrets management tools/functionality such as "
    recommendation += "AWS Secrets Manager to retrieve sensitive values or credentials when required, rather than hardcoding contents."

    gitleaks_issues = json.load(gitleaks_file)

    for issue in gitleaks_issues:

        title = issue["rule"]
        title = f'{issue["rule"]} found at {issue["file"]}'
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
            if "/" in issue["file"]:
                location += f'/blob/{issue["commit"]}/{issue["file"]}'
                if issue["lineNumber"] > 0:
                    location += f'#L{issue["lineNumber"]}'

        filename = issue["file"]

        issue_holder.add(
            issue_type,
            tool_name,
            title,
            description,
            location,
            recommendation,
            filename,
            severity = severity,
            raw_output = issue
        )

    logger.debug(f"> gitleaks: {len(gitleaks_issues)} issues reported\n")