"""Single source of truth for publicly known default IoT/router/SSH credentials.

The learned detector consumes this as a feature input ("is this credential pair
publicly known to be a default"), which is ordinary domain-driven feature
engineering rather than rule-based decision logic: the weight on the resulting
`weak_credential_hits` feature is *learned*, not hard-set. The attack toolkit in
``attacks/`` loads the very same list so that attacker and defender agree on what
counts as "known weak" (see ``attacks/realistic``).

Every pair here is publicly documented vendor-default / top-password-list
material. Keep it modest and bounded; it is reference data, never a live secret.
"""

# (username, password) pairs, compared case-sensitively after stripping.
KNOWN_WEAK_CREDENTIALS: frozenset[tuple[str, str]] = frozenset(
    {
        # Generic administrative defaults.
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "1234"),
        ("admin", "12345"),
        ("admin", "123456"),
        ("admin", ""),
        ("admin", "admin123"),
        ("admin", "pass"),
        ("administrator", "administrator"),
        ("administrator", "password"),
        # Unix / SSH defaults.
        ("root", "root"),
        ("root", "toor"),
        ("root", "admin"),
        ("root", "password"),
        ("root", "1234"),
        ("root", "root123"),
        ("root", ""),
        ("user", "user"),
        ("test", "test"),
        ("guest", "guest"),
        # Raspberry Pi / SBC defaults.
        ("pi", "raspberry"),
        ("ubuntu", "ubuntu"),
        # IoT camera / DVR / router vendor defaults (publicly documented).
        ("admin", "admin1234"),
        ("admin", "9999"),
        ("admin", "4321"),
        ("admin", "meinsm"),
        ("root", "xc3511"),
        ("root", "vizxv"),
        ("root", "888888"),
        ("root", "54321"),
        ("root", "12345"),
        ("support", "support"),
        ("service", "service"),
        ("ubnt", "ubnt"),
        ("cisco", "cisco"),
        ("tech", "tech"),
        ("admin", "airlive"),
        ("admin", "cameable"),
    }
)


def _normalize(value: object) -> str:
    return str(value).strip() if value is not None else ""


def is_known_weak(username: object, password: object) -> bool:
    """Return True when (username, password) is a publicly known default pair.

    Matching is independent of the event outcome: an accepted *or* rejected login
    using a default pair is equally a "known weak credential" observation, which
    mirrors the historical rule the learned policy replaces.
    """
    return (_normalize(username), _normalize(password)) in KNOWN_WEAK_CREDENTIALS
