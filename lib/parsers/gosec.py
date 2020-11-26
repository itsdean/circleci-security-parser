import json

from ..constants import calculate_rating

"""
G101: Look for hard coded credentials
G102: Bind to all interfaces
G103: Audit the use of unsafe block
G104: Audit errors not checked
G106: Audit the use of ssh.InsecureIgnoreHostKey
G107: Url provided to HTTP request as taint input
G108: Profiling endpoint automatically exposed on /debug/pprof
G109: Potential Integer overflow made by strconv.Atoi result conversion to int16/32
G110: Potential DoS vulnerability via decompression bomb
G201: SQL query construction using format string
G202: SQL query construction using string concatenation
G203: Use of unescaped data in HTML templates
G204: Audit use of command execution
G301: Poor file permissions used when creating a directory
G302: Poor file permissions used with chmod
G303: Creating tempfile using a predictable path
G304: File path provided as taint input
G305: File traversal when extracting zip/tar archive
G306: Poor file permissions used when writing to a new file
G307: Deferring a method which returns an error
G401: Detect the usage of DES, RC4, MD5 or SHA1
G402: Look for bad TLS connection settings
G403: Ensure minimum RSA key length of 2048 bits
G404: Insecure random number source (rand)
G501: Import blocklist: crypto/md5
G502: Import blocklist: crypto/des
G503: Import blocklist: crypto/rc4
G504: Import blocklist: net/http/cgi
G505: Import blocklist: crypto/sha1
G601: Implicit memory aliasing of items from a range statement
"""


# A dictionary of tuples, where each tuple maps to (description, recommendation). description and recommendation are both custom.
rule_id_sets = {
    "G101": (
        "The line(s) contained a potentially hardcoded sensitive value. Should an attacker obtain an instance of the codebase (either via the source repository or a compiled asset) then they may leverage the value to carry out further compromise and move further within the systems in scope.\n\nFurthermore, for both security and functionality reasons, should the value become invalid then the code base will have to be updated each time to accomodate for the new value (as opposed to pulling the value off a fixed-name environment variable)",
        "Sensitive values should not be stored within codebases and version control systems; ideally, such values should only be obtained at runtime and/or when required, such as via an environment variable."
    ),
    "G102": (
        "The line(s) appeared to bind a network listener service to all interfaces.\nBinding to all interfaces may open up a service to access via unexpected avenues, which may not make use of all existing security features surrounding the service.",
        "Explicitly bind such services on a per-interface basis, to ensure that listeners are only serving via known/expected methods."
    ),
    "G103": (
        "The Go module \"unsafe\" was identified to be in use.",
        "Confirm the usage of the module is required for the project in scope to function."
    ),
    "G104": (
        "Potential errors or exceptions that could come from a function call were not directly handled. This may be due to using _ to blanket accept all variables other than what was required, which includes any thrown errors.",
        "Explicitly catch errors that may be thrown and introduce logic to deal with or report the error."
    ),
    "G201": ( # sql injection
        "An instance of SQL injection was identifed; a match for a SQL query was found, where a portion of the query itself could be manipulated and altered via a passed parameter. Should an attacker have control over the value of this parameter, it may be possible for an attacker to execute arbitrary SQL queries and access information they should not have access to by default.",
        "It is strongly recommended not to use string concatenation or string formatting (via fmt.Sprintf) when crafting SQL queries. Where the manipulation or alteration of SQL queries is required (such as a SELECT query where the conditional is not static), make use of argument placeholders.\n\nMore information can be found at https://securego.io/docs/rules/g201-g202.html"
    ),
    "G401": (
        "Usage of an insecure cryptographic or hashing method was identified.",
        "Confirm that the identified modules are not used to deal with sensitive data, such as passwords or personal information. If this is the case, then use a more secure implementation (i.e. SHA512 rather than SHA1) when dealing with such information."
    )
}


# Some codes will link to a similar issue so we can re-use descriptions and recommendations.
# Catch SQL injection
rule_id_sets["G202"] = rule_id_sets["G201"]
# Catch all blacklisted crypto/hashing imports/usages
rule_id_sets["G501"] = rule_id_sets["G401"]
rule_id_sets["G502"] = rule_id_sets["G401"]
rule_id_sets["G503"] = rule_id_sets["G401"]
# rule_id_sets["G504"] = rule_id_sets["G401"]
rule_id_sets["G505"] = rule_id_sets["G401"]


def get_issue_information(rule_id):
    """
    Creates boilerplate content for an issue and uses primitive templating to provide metavariables within parsed gosec issues.
    """

    # Get the custom description and recommendation for the issue, depending on its rule_id value. If there isn't a custom writeup, then use the generic text.
    if rule_id in rule_id_sets.keys():
        return "\n" + rule_id_sets[rule_id][0], rule_id_sets[rule_id][1]
    else:
        return "", ""

def parse(gosec_file, issue_holder, logger, metadata):
    issue_type = "code"
    tool_name = "gosec"

    json_object = json.load(gosec_file)

    issues = json_object["Issues"]

    for issue in issues:

        custom = {}

        severity = "Medium"

        title = issue["details"]
        line = issue["line"]
        rule_id = issue["rule_id"]

        repository_location = metadata.repository_url
        repository_name = metadata.repository
        commit = metadata.commit_hash

        # The minimum severity is medium, but if the issue's severity is higher we'll report that
        if calculate_rating(issue["severity"]) > calculate_rating(severity):
            severity = issue["severity"].capitalize()

        # Get the relative filepath (as gosec outputs the path from root upwards)
        file_location = issue["file"].split(repository_name + "/")[1]
        custom["file_location"] = file_location
        filename = file_location.split("/")[-1]

        description = f"A security issue was identified in line {line} of {filename}. "

        if rule_id in rule_id_sets.keys():
            description += f'The gosec rule_id that triggered was \"{rule_id}\".'
        else:
            description += f'The gosec rule_id that triggered was \"{rule_id}: {title}\".'

        description_rel, recommendation_rel = get_issue_information(
            rule_id
        )

        description += description_rel

        description += "\n\nThe offence can be found below:"
        if metadata.jira:
            description += "\n{code}\n" + issue["code"] + "\n{code}"
        else:
            description += f'\n{issue["code"]}'

        recommendation = f"Please investigate the reported file and line to confirm the nature of the issue."
        recommendation += f"\n{recommendation_rel}"

        # craft the exact location of the issue in the repository
        location = f'{repository_location}/blob/{commit}/{file_location}#L{line}'

        issue_holder.add(
            issue_type,
            tool_name,
            title,
            description,
            location,
            recommendation,
            raw_output = issue,
            severity = severity,
            custom = custom
        ) 

    logger.debug(f"> gosec: {len(issues)} issues reported\n")
