"""
Collecte HTTP pour l'audit Web.

Responsabilités :
- valider les URL ;
- effectuer les requêtes ;
- suivre les redirections de manière contrôlée ;
- conserver les erreurs ;
- empêcher la sortie du périmètre autorisé.
"""

from __future__ import annotations

from urllib.parse import urlparse

import requests

from app.security.web_scope import (
    is_domain_allowed,
)


class WebCollectionError(Exception):
    """
    Erreur de collecte Web.
    """


def validate_url(
    url: str
) -> tuple[bool, str | None]:
    """
    Valide une URL HTTP/HTTPS.
    """

    if not url:
        return False, "URL vide."

    try:
        parsed = urlparse(
            url.strip()
        )
    except ValueError:
        return False, "URL invalide."

    if parsed.scheme not in {
        "http",
        "https",
    }:
        return (
            False,
            "Seuls HTTP et HTTPS sont autorisés."
        )

    if not parsed.hostname:
        return (
            False,
            "Nom d'hôte manquant."
        )

    return True, None


def request_with_scope(
    url: str,
    allowed_domains: set[str],
    timeout: int = 10,
    max_redirects: int = 5,
) -> dict:
    """
    Effectue une requête GET en contrôlant
    chaque redirection avant de la suivre.
    """

    current_url = url

    redirects = []

    request_count = 0


    for _ in range(
        max_redirects + 1
    ):

        if not is_domain_allowed(
            current_url,
            allowed_domains
        ):
            raise WebCollectionError(
                (
                    "URL hors périmètre autorisé : "
                    f"{current_url}"
                )
            )


        try:

            response = requests.get(
                current_url,
                timeout=timeout,
                allow_redirects=False,
            )

            request_count += 1


        except requests.exceptions.SSLError as error:
            raise WebCollectionError(
                f"TLS_ERROR: {error}"
            ) from error


        except requests.exceptions.ConnectTimeout as error:
            raise WebCollectionError(
                f"CONNECTION_TIMEOUT: {error}"
            ) from error


        except requests.exceptions.ReadTimeout as error:
            raise WebCollectionError(
                f"READ_TIMEOUT: {error}"
            ) from error


        except requests.exceptions.ConnectionError as error:
            raise WebCollectionError(
                f"CONNECTION_ERROR: {error}"
            ) from error


        except requests.RequestException as error:
            raise WebCollectionError(
                f"REQUEST_ERROR: {error}"
            ) from error


        # ----------------------------------------------------
        # REDIRECTION
        # ----------------------------------------------------

        if response.is_redirect or response.is_permanent_redirect:

            location = response.headers.get(
                "Location"
            )

            if not location:
                return {
                    "response": response,
                    "final_url": current_url,
                    "redirects": redirects,
                    "request_count": request_count,
                }


            next_url = requests.compat.urljoin(
                current_url,
                location
            )


            if not is_domain_allowed(
                next_url,
                allowed_domains
            ):

                redirects.append(
                    {
                        "status_code": (
                            response.status_code
                        ),
                        "url": current_url,
                        "location": next_url,
                        "allowed": False,
                    }
                )

                raise WebCollectionError(
                    (
                        "Redirection hors périmètre "
                        f"bloquée : {next_url}"
                    )
                )


            redirects.append(
                {
                    "status_code": (
                        response.status_code
                    ),
                    "url": current_url,
                    "location": next_url,
                    "allowed": True,
                }
            )


            current_url = next_url

            continue


        # ----------------------------------------------------
        # RÉPONSE FINALE
        # ----------------------------------------------------

        return {
            "response": response,
            "final_url": current_url,
            "redirects": redirects,
            "request_count": request_count,
        }


    raise WebCollectionError(
        "Nombre maximal de redirections dépassé."
    )