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

    if "vulnerabilities" in json_object:
        vulnerabilities = json_object["vulnerabilities"]

        for vuln in vulnerabilities:
            title = vuln["longMessage"].split(". ")[0]

            # Combine the issue descriptions from insider-cli first, then add the code after
            description = vuln["longMessage"].split(". ")[1] + "\n"
            description += "\nAn example of the offending code can be seen below:\n" + vuln["method"]

            # if "affectedFiles" in vuln.keys():
            #     location = ", ".join(vuln["affectedFiles"])
            # else:
            #     location = vuln["classMessage"]

            location = vuln["classMessage"].split(" (")[0]

            recommendation = vuln["shortMessage"]

            rating = vuln["cvss"]
            severity = convert_cvss(rating)
            # print(str_rating)

            issue_holder.add(
                issue_type,
                tool_name,
                title,
                description,
                location,
                recommendation,
                raw_output = vuln,
                severity = severity
            )

    if "sca" in json_object:
        dependencies = json_object["sca"]
        issue_type = "dependencies"

        for dependency in dependencies:

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
                cve_value = cve
            )

    logger.debug(f"> insider: {len(vulnerabilities) + len(dependencies)} issues reported\n")