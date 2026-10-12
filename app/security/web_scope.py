"""
Gestion du périmètre autorisé pour l'audit Web.
"""

from urllib.parse import urlparse, urljoin


EXCLUDED_ACTION_KEYWORDS = {
    "logout",
    "signout",
    "delete",
    "remove",
    "destroy",
    "purchase",
    "checkout",
    "buy",
    "send-message",
    "send_message",
}


def normalize_hostname(
    hostname: str | None
) -> str:
    if not hostname:
        return ""

    hostname = hostname.lower().strip()

    if hostname.startswith("www."):
        hostname = hostname[4:]

    return hostname


def get_hostname(
    url: str
) -> str:
    try:
        return normalize_hostname(
            urlparse(url).hostname
        )
    except ValueError:
        return ""


def build_allowed_domains(
    start_url: str,
    extra_domains: list[str] | None = None
) -> set[str]:
    """
    Construit la liste des domaines autorisés.
    """

    allowed = set()

    start_host = get_hostname(
        start_url
    )

    if start_host:
        allowed.add(
            start_host
        )

    for domain in (
        extra_domains or []
    ):
        normalized = normalize_hostname(
            domain
        )

        if normalized:
            allowed.add(
                normalized
            )

    return allowed


def is_domain_allowed(
    url: str,
    allowed_domains: set[str]
) -> bool:
    """
    Vérifie que l'URL reste dans le périmètre.
    """

    hostname = get_hostname(
        url
    )

    return (
        bool(hostname)
        and hostname in allowed_domains
    )


def resolve_url(
    base_url: str,
    candidate: str
) -> str:
    """
    Convertit une URL relative en URL absolue.
    """

    return urljoin(
        base_url,
        candidate
    )


def should_exclude_url(
    url: str
) -> bool:
    """
    Exclut par défaut les actions potentiellement
    destructrices ou modifiant l'état.
    """

    lowered = url.lower()

    return any(
        keyword in lowered
        for keyword
        in EXCLUDED_ACTION_KEYWORDS
    )