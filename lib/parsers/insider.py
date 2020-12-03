import json

from lib.constants import convert_cvss


def convert_severity(severity):
    if severity == "moderate":
        return "medium"
    else:
        return severity


def parse(input_file, issue_holder, logger):
    """
    Goes through findings reported by insider-cli and passes issues to Reporter
    for output standardisation
    """

    issue_type = "code"
    tool_name = "insider"

    json_object = json.load(input_file)

    vulnerabilities = []
    if "vulnerabilities" in json_object:
        vulnerabilities = json_object["vulnerabilities"]

        for vuln in vulnerabilities:

            custom = {
                "type": "vulnerability"
            }

            # This is the full path to the file
            location = vuln["classMessage"].split(" (")[0]

            # This is just the filename
            filename = location.rsplit("/")[-1]

            title = vuln["longMessage"].split(". ")[0]
            if "Generic API key" in title:
                custom["type"] = "credential"
                custom["filename"] = filename
                custom["line"] = vuln["line"]
                title += f" found at \"{filename}\""

            # Combine the issue descriptions from insider-cli first, then add the code after
            description = vuln["longMessage"].split(". ")[1] + "\n"
            if "method" in vuln:
                description += "\nAn example of the offending code can be seen below:\n" + vuln["method"]

            # if "affectedFiles" in vuln.keys():
            #     location = ", ".join(vuln["affectedFiles"])
            # else:
            #     location = vuln["classMessage"]


            if "shortMessage" in vuln:
                recommendation = vuln["shortMessage"]
            else:
                recommendation = "Please look at and confirm the validity of this issue."

            rating = vuln["cvss"]
            severity = convert_cvss(rating)

            issue_holder.add(
                issue_type,
                tool_name,
                title,
                description,
                location,
                recommendation,
                raw_output = vuln,
                severity = severity,
                custom = custom
            )

    dependencies = []
    if "sca" in json_object:
        dependencies = json_object["sca"]
        issue_type = "dependencies"

        for dependency in dependencies:

            custom = {
                "type": "dependency"
            }

            if dependency["cves"] != "":
                cve = dependency["cves"]
            else:
                cve = "n/a"

            title = dependency["title"]
            description = dependency["description"]
            location = title.split(" - ")[1]
            recommendation = dependency["recomendation"]
            severity = convert_severity(dependency["severity"])

            issue_holder.add(
                issue_type,
                tool_name,
                title,
                description,
                location,
                recommendation,
                raw_output = dependency,
                severity = severity,
                cve_value = cve,
                custom = custom
            )

    logger.debug(f"> insider: {len(vulnerabilities) + len(dependencies)} issues reported\n")