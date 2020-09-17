import json
import traceback

def parse(nancy_file, issue_holder, logger):
    """
    Goes through sonatype-nancy output and reports any dependency issues
    """

    issue_type = "dependencies"
    tool_name = "nancy"

    try:
        json_object = json.load(nancy_file)

        # Go through all reported dependencies
        for dependency in json_object["vulnerable"]:

            if len(dependency["Vulnerabilities"]) > 0:

                # Remove the "pkg:golang/" prefix from the dependency name
                name_and_version = dependency["Coordinates"].split("pkg:golang/")[1]

                title = "Use of vulnerable Go dependency - " + name_and_version

                name = name_and_version.split("@")[0]

                # The location of the dependency is the name of itself.
                location = name

                version = name_and_version.split("@")[1]

                recommendation = "Update " + name + " to the latest stable version to ensure the project makes use of the latest security patches and fixes that the new version comes with.\n\nIf it is not possible to update the dependency, then consider the risk exposed to the business and project.\nAlso, as a last case consider identifying and using alernative dependencies that provide similar functionality albeit without the original vulnerability."

                description = "Version " + version + " of " + name + ", a Go dependency pulled by the scanned project, was found to be vulnerable to security issues. Such vulnerabilities have been listed below.\n\n"

                # For each vulnerability, add its title and a short description to
                # the general description string. Add in the link too for more info.
                for vulnerability in dependency["Vulnerabilities"]:
                    description += vulnerability["Title"] + "\n"
                    description += vulnerability["Description"]
                    description += "\nFurther information can be found at " + vulnerability["Reference"] + "\n\n"

                    if vulnerability["Cve"] != "":
                        cve_value = vulnerability["Cve"]
                    else:
                        cve_value = ""

                issue_holder.add(
                    issue_type,
                    tool_name,
                    title,
                    description,
                    location,
                    recommendation,
                    cve_value = cve_value
                )

        logger.debug(f"> nancy: {json_object['num_vulnerable']} issues reported\n")

    except json.decoder.JSONDecodeError as ex:

        t = traceback.format_exc().split("\n")

        logger.warning("The parser wasn't able to parse JSON from the Nancy output. Please have a look at the following traceback:")

        for line in t:
            logger.warning(line)
