"""
Parses JSON-format output provided by Gosec, a golang security checker that leverages Go's internal AST tree system.
"""

"""
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
G305: File traversal when extracting zip archive
G402: Look for bad TLS connection settings
G403: Ensure minimum RSA key length of 2048 bits
G404: Insecure random number source (rand)
G504: Import blacklist: net/http/cgi
"""

rule_id_sets = {
    "G101": (
        "Line <<line>> of <<file>> contained a potentially hardcoded sensitive value. Should an attacker obtain an instance of the codebase (either via the source repository or a compiled asset) then they may leverage the value to carry out further compromise and move further within the systems in scope.\n\nFurthermore, for both security and functionality reasons, should the value become invalid then the code base will have to be updated each time to accomodate for the new value (as opposed to pulling the value off a fixed-name environment variable)",
        "Sensitive values should not be stored within codebases and version control systems; ideally, such values should only be obtained at runtime and/or when required, such as via an environment variable."
    ),
    "G102": (
        "Line <<line>> of <<file>> appeared to bind a network listener service to all interfaces.\n\nThe line in question can be found below:\n>> <<code>> <<\n\nBinding to all interfaces may open up a service to access via unexpected avenues, which may not make use of all existing security features surrounding the service.",
        "Explicitly bind such services on a per-interface basis, to ensure that listeners are only serving via known/expected methods."
    ),
    "G103": (
        "The Go module \"unsafe\" was identified to be in use.\nThe affected code can be found below:\n>> <<code>> <<",
        "Confirm the usage of the module is required for the project in scope to function."
    ),
    "G104": (
        "Potential errors or exceptions that could come from a function call were not directly handled. This may be due to using _ to blanket accept all variables other than what was required, which includes any thrown errors.\n\nThe affected code can be found below:\n>> <<code>> <<",
        "Explicitly catch errors that may be thrown and introduce logic to deal with or report the error."
    ),
    "G201": ( # sql injection
        "An instance of SQL injection was identifed; a match for a SQL query was found, where a portion of the query itself could be manipulated and altered via a passed parameter. Should an attacker have control over the value of this parameter, it may be possible for an attacker to execute arbitrary SQL queries and access information they should not have access to by default.\n\nThe affected line can be found below:\n>> <<code>> <<",
        "It is strongly recommended not to use string concatenation or string formatting (via fmt.Sprintf) when crafting SQL queries. Where the manipulation or alteration of SQL queries is required (such as a SELECT query where the conditional is not static), make use of argument placeholders.\n\nMore information can be found at https://securego.io/docs/rules/g201-g202.html"
    ),
    "G401": (
        "Usage of an insecure cryptographic or hashing method was identified.\n\nThe affected code can be found below:\n>> <<code>> <<",
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


def generate_issue(rule_id, filepath, line, code):

    description, recommendation = rule_id_sets.get(
        rule_id,
        (
            "A security issue was identified at line <<line>> of <<file>>.\n\nThe title of this issue explains the situation, while the actual code line in question can be found below:\n>> <<code>> <<\n",
            "Please investigate the reported file and line to confirm the nature of the issue."
        )
    )
    description = description.replace("<<file>>", filepath).replace("<<line>>", line).replace("<<code>>", code)
 
    return description, recommendation

def parse(i_file, reporter):
    """
    Opens gosec output (assuming it's in JSON format) and attempts to identify raised issues, passing it to the parser reporter.
    """

    import json

    issue_type = "code"
    tool_name = "gosec"

    json_object = json.load(i_file)

    issues = json_object["Issues"]

    for issue in issues:
        
        title = issue["details"]
        location = issue["file"] + ":" + issue["line"]
        
        description, recommendation = generate_issue( 
            issue["rule_id"],
            issue["file"],
            issue["line"],
            issue["code"]
        )
        
        recommendation += "\n\nNote: If this is a false positive, add #nosec to the code line or block to prevent it from being reported again."

        print(description)
        print(recommendation)
        print("---")

        severity = issue["severity"].lower().capitalize()

        reporter.add(
            issue_type,
            tool_name,
            title,
            description,
            location,
            recommendation,
            raw_output = issue,
            severity = severity
        )