import json

def parse(burrow_file, issue_holder, logger):
    """
    Goes through burrow tool output and passes each reported issue to Reporter.
    """

    # Set the "constants now"
    issue_type = "secrets"
    tool_name = "burrow"

    # Without 100% confidence we don't want to recommend removing the line. 
    # We'll leave it up to manual work to triage this.
    recommendation = "Please identify whether this finding is valid; consider adding the file and line to .burrowignore if this is a false positive."

    # Because burrow_file is a File object, we need the filename for outputting reasons. 
    filename = burrow_file.name # Do I need to do this? How often am I called?

    # Unmarshal the file into a JSON object
    json_object = json.load(burrow_file)

    # Get the reported issues from the JSON blob.
    findings = json_object["findings"]

    for issue in findings:
        
        title = issue["match"]
        location = issue["file"]

        description = "A potentially hardcoded secret was identified."

        # Check if the issue output included an affected line
        # If it did, add the line to the path.
        if isinstance(
            issue["line"],
            int
        ):
            location += ":" + str(issue["line"])

        issue_holder.add(
            issue_type,
            tool_name,
            title,
            description,
            location,
            recommendation,
            filename,
            raw_output = issue
        )

    logger.debug(f"> burrow: {len(findings)} issues reported\n")