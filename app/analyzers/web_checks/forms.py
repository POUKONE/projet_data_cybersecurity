from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup


SENSITIVE_FIELD_KEYWORDS = {
    "password",
    "passwd",
    "pwd",
    "card",
    "credit",
    "cvv",
    "cvc",
    "iban",
    "token",
    "secret",
}


def make_check(
    check_id: str,
    name: str,
    status: str,
    message: str,
) -> dict:
    return {
        "check_id": check_id,
        "name": name,
        "status": status,
        "message": message,
    }


def extract_forms(
    html: str,
    page_url: str,
) -> list[dict]:
    """
    Extrait les formulaires présents dans une page HTML.
    """

    soup = BeautifulSoup(
        html or "",
        "html.parser"
    )

    forms = []

    for index, form in enumerate(
        soup.find_all("form"),
        start=1
    ):

        method = (
            form.get("method", "GET")
            .upper()
            .strip()
        )

        action = (
            form.get("action")
            or page_url
        )

        action_url = urljoin(
            page_url,
            action
        )

        fields = []

        for field in form.find_all(
            [
                "input",
                "select",
                "textarea",
            ]
        ):

            field_name = (
                field.get("name")
                or ""
            )

            field_type = (
                field.get("type")
                or field.name
            ).lower()

            fields.append(
                {
                    "name": field_name,
                    "type": field_type,
                }
            )

        forms.append(
            {
                "id": index,
                "method": method,
                "action": action_url,
                "fields": fields,
            }
        )

    return forms


def is_sensitive_form(
    form: dict
) -> bool:
    """
    Détermine si un formulaire contient
    des champs potentiellement sensibles.
    """

    for field in form.get(
        "fields",
        []
    ):
        name = (
            field.get("name", "")
            .lower()
        )

        field_type = (
            field.get("type", "")
            .lower()
        )

        if field_type == "password":
            return True

        if any(
            keyword in name
            for keyword
            in SENSITIVE_FIELD_KEYWORDS
        ):
            return True

    return False


def check_forms_security(
    html: str,
    page_url: str,
) -> dict:
    """
    Analyse passivement les formulaires.

    Vérifie notamment :
    - inventaire ;
    - méthode HTTP ;
    - destination ;
    - formulaire sensible envoyé en HTTP.
    """

    checks = []
    findings = []

    forms = extract_forms(
        html=html,
        page_url=page_url,
    )

    if not forms:

        checks.append(
            make_check(
                "FORMS_PRESENT",
                "Présence de formulaires",
                "SKIPPED",
                "Aucun formulaire détecté sur cette page.",
            )
        )

        return {
            "checks": checks,
            "findings": findings,
            "forms": [],
        }

    checks.append(
        make_check(
            "FORMS_PRESENT",
            "Présence de formulaires",
            "PASSED",
            f"{len(forms)} formulaire(s) détecté(s).",
        )
    )

    for form in forms:

        sensitive = is_sensitive_form(
            form
        )

        action = form[
            "action"
        ]

        action_scheme = (
            urlparse(
                action
            ).scheme.lower()
        )

        page_scheme = (
            urlparse(
                page_url
            ).scheme.lower()
        )

        if (
            sensitive
            and (
                action_scheme == "http"
                or page_scheme == "http"
            )
        ):

            findings.append(
                {
                    "event_type": (
                        "SENSITIVE_FORM_OVER_HTTP"
                    ),
                    "source_type": "WEB",
                    "target": page_url,
                    "url": page_url,
                    "parameter": None,
                    "classification": (
                        "MISCONFIGURATION"
                    ),
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "message": (
                        "Un formulaire contenant des champs "
                        "potentiellement sensibles est transmis "
                        "via HTTP."
                    ),
                    "description": (
                        "Les données saisies peuvent transiter "
                        "sans protection TLS."
                    ),
                    "evidence": (
                        f"Méthode={form['method']}, "
                        f"action={action}"
                    ),
                    "recommendation": (
                        "Servir la page et la destination du "
                        "formulaire uniquement via HTTPS."
                    ),
                    "validation_method": (
                        "Inspecter manuellement le formulaire "
                        "et sa destination."
                    ),
                    "status": "OPEN",
                }
            )

    checks.append(
        make_check(
            "FORM_TRANSPORT_SECURITY",
            "Transport des formulaires sensibles",
            (
                "FAILED"
                if findings
                else "PASSED"
            ),
            (
                f"{len(findings)} problème(s) détecté(s)."
                if findings
                else (
                    "Aucun formulaire sensible transmis "
                    "en HTTP détecté."
                )
            ),
        )
    )

    return {
        "checks": checks,
        "findings": findings,
        "forms": forms,
    }