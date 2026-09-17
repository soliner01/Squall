"""Vulnerability rule definitions.

Each rule is a plain dataclass-ish dict so that adding a new check is just a matter of appending an entry - no scanner changes required. 
Patterns are compiled regexes; the languages field restricts a rule to certain file extensions (None means apply to all supported languages).
"""

import re

# ---------------------------------------------------------------------------
# Severity ordering - used by the reporter to sort and colorize findings.
# ---------------------------------------------------------------------------
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _r(rule_id, name, severity, pattern, description, languages=None, fix=None):
    # Small helper to keep the rule table below readable and consistent.
    return {
        "id": rule_id,
        "name": name,
        "severity": severity,
        "pattern": re.compile(pattern, re.IGNORECASE),
        "description": description,
        "languages": languages,  # None => applies to all supported files
        "fix": fix or "",
    }


# ---------------------------------------------------------------------------
# The rule set
# C# is the primary target, but several rules are language-agnostic (hardcoded secrets, weak crypto names) and a handful are specific to JS/Python/etc.
# The scanner matches a rule only against files whose extension is in the rule's languages set (or if the set is None).
# ---------------------------------------------------------------------------
RULES = [
    # SQL injection ---------------------------------------------------------
    _r(
        "SQL001",
        "SQL query built with string concatenation",
        "critical",
        r"(?:SqlCommand|OleDbCommand|OdbcCommand)\s*\(\s*[^)]*?\+",
        "An SQL command appears to be assembled via string concatenation, which is the classic vector for injection.",
        languages={".cs"},
        fix="Use parameterized queries (@param placeholders) instead."
    ),
    _r(
        "SQL002",
        "Inline SQL with interpolated/concatenated string",
        "critical",
        r'"\s*SELECT\s+.*?"\s*\+\s*|"\s*INSERT\s+.*?"\s*\+\s*|"\s*UPDATE\s+.*?"\s*\+\s*|"\s*DELETE\s+.*?"\s*\+\s*',
        "An SQL statement literal is concatenated with a runtime value. Even a single unparameterized input makes the query injectable.",
        languages={".cs", ".vb"},
    ),
    _r(
        "SQL003",
        "ExecuteNonQuery / ExecuteReader on concatenated string",
        "high",
        r"Execute(?:NonQuery|Reader|Scalar)\s*\(\s*[^)]*?\+",
        "A database execute call receives a concatenated string rather than a parameterized command object.",
        languages={".cs"},
    ),

    # Hardcoded secrets ----------------------------------------------------
    _r(
        "SEC001",
        "Hardcoded password / API key assignment",
        "high",
        r'(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\s*=\s*["\'][^"\']{4,}["\']',
        "A credential-like variable is assigned a literal string.",
        fix="Move secrets to environment variables or a secrets manager and never commit them to source control."
    ),
    _r(
        "SEC002",
        "Connection string with embedded credentials",
        "high",
        r'(?:connectionstring|connstring|connection_string)\s*=\s*["\'][^"\']*(?:password|pwd|uid|user\s*id)=[^"\']+["\']',
        "The connection string contains a plaintext username/password pair. Pull credentials from configuration or key vault instead.",
    ),

    # Weak cryptography ---------------------------------------------------
    _r(
        "CRY001",
        "MD5 used for hashing",
        "medium",
        r"\bMD5\b",
        "MD5 is cryptographically broken and unsuitable for any security purpose.",
        languages={".cs", ".java", ".py", ".js", ".ts", ".go", ".php", ".rb"},
        fix="Use SHA-256 or stronger, and salt password hashes."
    ),
    _r(
        "CRY002",
        "SHA-1 used for hashing",
        "medium",
        r"\bSHA1\b|\bSHA-1\b",
        "SHA-1 is no longer collision-resistant. Prefer SHA-256 or stronger.",
        languages={".cs", ".java", ".py", ".js", ".ts", ".go", ".php", ".rb"},
        fix="Use a stronger hashing algorithm, such as SHA-256."
    ),
    _r(
        "CRY003",
        "Weak symmetric algorithm (DES / 3DES / RC2)",
        "high",
        r"\b(?:DES|TripleDES|RC2)\b",
        "DES-family ciphers are obsolete and trivially broken.",
        languages={".cs", ".java", ".py", ".js", ".ts", ".go", ".php"},
        fix="Use AES (AesManaged / AesCryptoServiceProvider) with a 256-bit key."
    ),
    _r(
        "CRY004",
        "Insecure PRNG used where a CSPRNG is required",
        "medium",
        r"\bnew\s+Random\s*\(",
        "System.Random is not cryptographically secure. For tokens, nonces, or password reset codes, use RNGCryptoServiceProvider or RandomNumberGenerator.",
        languages={".cs"},
        fix="Change the System.Random call to RNGCryptoServiceProvider or RandomNumberGenerator."
    ),

    # Certificate / TLS validation ---------------------------------------
    _r(
        "TLS001",
        "Certificate validation callback disabled",
        "critical",
        r"ServerCertificateValidationCallback\s*=\s*[^;]*?(?:true|=>\s*true)",
        "The SSL certificate validation callback is forced to return true, which silently trusts every certificate and defeats TLS entirely.",
        languages={".cs"},
        fix="Remove the override and allow .NET to handle validation, as it does so securely."
    ),
    _r(
        "TLS002",
        "TLS protocol version forced to a deprecated value",
        "high",
        r"SecurityProtocol\s*=\s*(?:Ssl3|Tls|Tls11)",
        "A legacy TLS protocol is explicitly enabled, which carries security risks.",
        languages={".cs"},
        fix="Require TLS 1.2 or above (Tls12 / Tls13)."
    ),

    # Command / process injection ----------------------------------------
    _r(
        "CMD001",
        "Process.Start with concatenated arguments",
        "high",
        r"Process\.Start\s*\([^)]*?\+",
        "Process.Start receives a concatenated string, allowing an attacker who controls the input to inject arbitrary arguments or commands.",
        languages={".cs"},
        fix="Use ProcessStartInfo.ArgumentList instead (if available)."
    ),
    _r(
        "CMD002",
        "Shell execute with shell=True / os.system",
        "high",
        r"os\.system\s*\(|subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True",
        "A shell is spawned with a string built from user-controllable input.",
        languages={".py"},
        fix="Pass an argument list and keep shell=False."
    ),

    # Insecure deserialization -------------------------------------------
    _r(
        "DES001",
        "BinaryFormatter deserialization",
        "critical",
        r"BinaryFormatter",
        "BinaryFormatter is unsafe by design - deserializing untrusted data with it leads directly to remote code execution.",
        languages={".cs"},
        fix="Use a modern serializer (System.Text.Json), and never deserialize untrusted input."
    ),
    _r(
        "DES002",
        "XmlSerializer on untrusted input",
        "high",
        r"XmlSerializer",
        "XmlSerializer can be dangerous when fed attacker-controlled XML (XXE / type-confusion).",
        languages={".cs"},
        fix="Validate the source and disable DTD processing."
    ),
    _r(
        "DES003",
        "pickle / yaml.load on untrusted data",
        "critical",
        r"pickle\.loads?\s*\(|yaml\.load\s*\(",
        "Deserializing untrusted pickle or YAML is equivalent to executing arbitrary code. Use json.load or yaml.safe_load instead.",
        languages={".py"},
        fix="Use json.load or yaml.safe_load instead."
    ),

    # Cross-site scripting ------------------------------------------------
    _r(
        "XSS001",
        "Raw HTML output in Razor view",
        "high",
        r"@Html\.Raw\s*\(",
        "Html.Raw writes unencoded content to the response. Only use it on trusted, sanitized markup - never on user input.",
        languages={".cshtml", ".vbhtml"},
    ),
    _r(
        "XSS002",
        "Response.Write with concatenation",
        "medium",
        r"Response\.Write\s*\([^)]*?\+",
        "Response.Write emits unencoded content. Encoding user input before writing avoids reflected XSS.",
        languages={".cs"},
    ),
    _r(
        "XSS003",
        "innerHTML assignment from dynamic value",
        "high",
        r"\.innerHTML\s*=\s*[^;]*?\+",
        "innerHTML is assigned a concatenated value, opening the page to DOM XSS.",
        languages={".js", ".ts", ".jsx", ".tsx"},
        fix="Use textContent or sanitize the input."
    ),

    # Path traversal -----------------------------------------------------
    _r(
        "PTH001",
        "Path.Combine with user-controlled segment",
        "medium",
        r"Path\.Combine\s*\([^)]*?(?:Request|QueryString|Form|Params)",
        "Path.Combine is fed a value drawn from request data, which can escape the intended directory (../../).",
        languages={".cs"},
        fix="Canonicalize and validate the resulting path stays inside the allowed root."
    ),

    # Open redirect ------------------------------------------------------
    _r(
        "RED001",
        "Response.Redirect with request data",
        "medium",
        r"Response\.Redirect\s*\([^)]*?(?:Request|QueryString|Form)",
        "Redirecting to a URL taken directly from the request enables open redirect attacks.",
        languages={".cs"},
        fix="Validate against an allow-list of destinations."
    ),

    # XXE -----------------------------------------------------------------
    _r(
        "XXE001",
        "XmlDocument / XPathDocument without secure settings",
        "high",
        r"new\s+Xml(?:Document|TextReader|PathDocument)\s*\(",
        "XML parsing without explicitly disabling DTDs is vulnerable to XXE and billion-laughs.",
        languages={".cs"},
        fix="Set XmlReaderSettings.DtdProcessing = Prohibit."
    ),

    # Debug / diagnostics left in ----------------------------------------
    _r(
        "DBG001",
        "Debugger.Break in source",
        "low",
        r"Debugger\.Break\s*\(\s*\)",
        "A hard debugger break is left in the code. Remove before shipping - it will hang production processes.",
        languages={".cs"},
    ),
    _r(
        "DBG002",
        "Debug.Assert / Trace.WriteLine in source",
        "low",
        r"\bDebug\.Assert|\bTrace\.WriteLine",
        "Diagnostic calls are present. Confirm these are stripped from release builds (they are by default, but it's still worth checking).",
        languages={".cs"},
    ),

    # eval / dynamic code -------------------------------------------------
    _r(
        "EVL001",
        "eval() on dynamic input",
        "critical",
        r"\beval\s*\(",
        "eval executes arbitrary code. If the argument is even partially user-controlled, this enables RCE.",
        languages={".js", ".ts", ".jsx", ".tsx", ".py"},
        fix="Replace eval with a safe parser."
    ),
]


# Types of files the program scans. More can be added, but keeping this list specific avoids scanning binaries, build artifacts, and noise, which aren't worth scanning.
SUPPORTED_EXTENSIONS = {
    # C# family
    ".cs", ".cshtml", ".vbhtml", ".vb",
    # JVM
    ".java", ".kt", ".scala",
    # Scripting / web
    ".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb",
    # Systems
    ".go", ".rs", ".c", ".cpp", ".h", ".hpp",
}
