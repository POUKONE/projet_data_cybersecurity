"""
Collecte HTTP et crawl passif contrôlé.

Responsabilités :
- validation des URL ;
- requêtes HTTP ;
- contrôle strict des redirections ;
- maintien dans le périmètre autorisé ;
- extraction des liens internes ;
- déduplication ;
- limites de profondeur ;
- limite du nombre de pages ;
- limite de durée ;
- limitation du débit ;
- exclusion d'actions potentiellement destructrices.

Aucune vérification active n'est exécutée ici.
"""

from __future__ import annotations

import time

from collections import deque
from urllib.parse import (
    urldefrag,
    urljoin,
    urlparse,
    urlunparse,
)

import requests

from bs4 import BeautifulSoup

from app.security.web_scope import (
    is_domain_allowed,
    should_exclude_url,
)


# ============================================================
# EXCEPTION
# ============================================================


class WebCollectionError(
    Exception
):
    """
    Erreur liée à la collecte HTTP ou au crawl.
    """


# ============================================================
# VALIDATION URL
# ============================================================


def validate_url(
    url: str,
) -> tuple[bool, str | None]:
    """
    Valide une URL HTTP ou HTTPS.
    """

    if not url:

        return (
            False,
            "URL vide.",
        )


    try:

        parsed = urlparse(
            url.strip()
        )

    except ValueError:

        return (
            False,
            "URL invalide.",
        )


    if parsed.scheme.lower() not in {
        "http",
        "https",
    }:

        return (
            False,
            "Seuls HTTP et HTTPS sont autorisés.",
        )


    if not parsed.hostname:

        return (
            False,
            "Nom d'hôte manquant.",
        )


    return (
        True,
        None,
    )


# ============================================================
# NORMALISATION URL
# ============================================================


def normalize_url(
    url: str,
) -> str:
    """
    Normalise une URL pour éviter les doublons.

    Les fragments #... sont supprimés.
    Le schéma et le hostname sont passés en minuscules.
    """

    clean_url, _ = urldefrag(
        url
    )


    parsed = urlparse(
        clean_url
    )


    scheme = (
        parsed.scheme.lower()
    )

    hostname = (
        parsed.hostname.lower()
        if parsed.hostname
        else ""
    )


    # --------------------------------------------------------
    # PORT
    # --------------------------------------------------------

    netloc = hostname


    if parsed.port:

        default_http = (
            scheme == "http"
            and parsed.port == 80
        )

        default_https = (
            scheme == "https"
            and parsed.port == 443
        )


        if not (
            default_http
            or default_https
        ):

            netloc = (
                f"{hostname}:{parsed.port}"
            )


    path = (
        parsed.path
        or "/"
    )


    normalized = urlunparse(
        (
            scheme,
            netloc,
            path,
            "",
            parsed.query,
            "",
        )
    )


    return normalized


# ============================================================
# EXTRACTION DES LIENS
# ============================================================


def extract_links(
    html: str,
    base_url: str,
) -> list[str]:
    """
    Extrait les liens HTTP/HTTPS d'une page HTML.
    """

    soup = BeautifulSoup(
        html or "",
        "html.parser",
    )


    links = []


    for anchor in soup.find_all(
        "a",
        href=True,
    ):

        href = (
            anchor.get(
                "href"
            )
            or ""
        ).strip()


        if not href:

            continue


        lowered = (
            href.lower()
        )


        # ----------------------------------------------------
        # SCHÉMAS NON NAVIGABLES
        # ----------------------------------------------------

        if lowered.startswith(
            (
                "mailto:",
                "tel:",
                "javascript:",
                "data:",
            )
        ):

            continue


        absolute_url = urljoin(
            base_url,
            href,
        )


        valid, _ = validate_url(
            absolute_url
        )


        if not valid:

            continue


        normalized = normalize_url(
            absolute_url
        )


        links.append(
            normalized
        )


    return links


# ============================================================
# REQUÊTE CONTRÔLÉE
# ============================================================


def request_with_scope(
    url: str,
    allowed_domains: set[str],
    timeout: int = 10,
    max_redirects: int = 5,
) -> dict:
    """
    Effectue une requête GET en vérifiant
    chaque redirection avant de la suivre.
    """

    current_url = normalize_url(
        url
    )

    redirects = []

    request_count = 0


    for _ in range(
        max_redirects + 1
    ):

        # ----------------------------------------------------
        # SCOPE
        # ----------------------------------------------------

        if not is_domain_allowed(
            current_url,
            allowed_domains,
        ):

            raise WebCollectionError(
                (
                    "URL hors périmètre autorisé : "
                    f"{current_url}"
                )
            )


        # ----------------------------------------------------
        # EXCLUSION
        # ----------------------------------------------------

        if should_exclude_url(
            current_url
        ):

            raise WebCollectionError(
                (
                    "URL exclue par la politique "
                    f"de sécurité : {current_url}"
                )
            )


        # ----------------------------------------------------
        # REQUÊTE
        # ----------------------------------------------------

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

        if (
            response.is_redirect
            or response.is_permanent_redirect
        ):

            location = (
                response.headers.get(
                    "Location"
                )
            )


            if not location:

                return {
                    "response": response,
                    "final_url": current_url,
                    "redirects": redirects,
                    "request_count": request_count,
                }


            next_url = normalize_url(
                urljoin(
                    current_url,
                    location,
                )
            )


            if not is_domain_allowed(
                next_url,
                allowed_domains,
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


            if should_exclude_url(
                next_url
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
                        "Redirection vers une action "
                        f"exclue bloquée : {next_url}"
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


            current_url = (
                next_url
            )

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


# ============================================================
# CRAWLER PASSIF
# ============================================================


def crawl_site(
    start_url: str,
    allowed_domains: set[str],
    max_depth: int = 2,
    max_pages: int = 20,
    max_duration_seconds: int = 30,
    delay_seconds: float = 0.2,
    timeout: int = 10,
) -> dict:
    """
    Explore passivement un site Web dans le périmètre autorisé.

    Contraintes :
    - GET uniquement ;
    - aucun formulaire soumis ;
    - aucun test actif ;
    - aucun lien hors périmètre ;
    - actions sensibles exclues ;
    - déduplication des URL ;
    - profondeur limitée ;
    - nombre de pages limité ;
    - durée limitée ;
    - délai entre les requêtes.

    Retour :
    {
        "pages": [...],
        "errors": [...],
        "skipped": [...],
        "request_count": int,
        "visited_count": int,
        "discovered_count": int,
        "duration_seconds": float
    }
    """

    valid, validation_error = (
        validate_url(
            start_url
        )
    )


    if not valid:

        raise WebCollectionError(
            (
                "INVALID_URL: "
                f"{validation_error}"
            )
        )


    normalized_start = normalize_url(
        start_url
    )


    if not is_domain_allowed(
        normalized_start,
        allowed_domains,
    ):

        raise WebCollectionError(
            (
                "URL initiale hors périmètre "
                f"autorisé : {normalized_start}"
            )
        )


    if should_exclude_url(
        normalized_start
    ):

        raise WebCollectionError(
            (
                "URL initiale exclue "
                f"par la politique : {normalized_start}"
            )
        )


    # ========================================================
    # STRUCTURES
    # ========================================================

    queue = deque(
        [
            (
                normalized_start,
                0,
            )
        ]
    )


    queued_urls = {
        normalized_start
    }


    visited_urls = set()


    pages = []

    errors = []

    skipped = []


    request_count = 0

    discovered_urls = {
        normalized_start
    }


    started_at = (
        time.monotonic()
    )


    # ========================================================
    # BOUCLE DU CRAWL
    # ========================================================

    while (
        queue
        and len(
            visited_urls
        ) < max_pages
    ):

        elapsed = (
            time.monotonic()
            - started_at
        )


        if (
            elapsed
            >= max_duration_seconds
        ):

            skipped.append(
                {
                    "url": None,
                    "reason": "MAX_DURATION_REACHED",
                }
            )

            break


        current_url, depth = (
            queue.popleft()
        )


        if current_url in visited_urls:

            continue


        # ----------------------------------------------------
        # PROFONDEUR
        # ----------------------------------------------------

        if depth > max_depth:

            skipped.append(
                {
                    "url": current_url,
                    "reason": "MAX_DEPTH_EXCEEDED",
                }
            )

            continue


        # ----------------------------------------------------
        # SCOPE
        # ----------------------------------------------------

        if not is_domain_allowed(
            current_url,
            allowed_domains,
        ):

            skipped.append(
                {
                    "url": current_url,
                    "reason": "OUT_OF_SCOPE",
                }
            )

            continue


        # ----------------------------------------------------
        # ACTIONS EXCLUES
        # ----------------------------------------------------

        if should_exclude_url(
            current_url
        ):

            skipped.append(
                {
                    "url": current_url,
                    "reason": "EXCLUDED_ACTION",
                }
            )

            continue


        # ----------------------------------------------------
        # COLLECTE
        # ----------------------------------------------------

        try:

            collection = (
                request_with_scope(
                    url=current_url,
                    allowed_domains=allowed_domains,
                    timeout=timeout,
                )
            )


        except WebCollectionError as error:

            visited_urls.add(
                current_url
            )

            errors.append(
                {
                    "url": current_url,
                    "message": str(
                        error
                    ),
                }
            )

            continue


        visited_urls.add(
            current_url
        )


        request_count += (
            collection.get(
                "request_count",
                0,
            )
        )


        response = collection[
            "response"
        ]


        final_url = normalize_url(
            collection[
                "final_url"
            ]
        )


        # ----------------------------------------------------
        # PAGE
        # ----------------------------------------------------

        content_type = (
            response.headers.get(
                "Content-Type",
                ""
            )
        )


        page = {
            "url": current_url,
            "final_url": final_url,
            "depth": depth,
            "status_code": (
                response.status_code
            ),
            "content_type": (
                content_type
            ),
            "redirects": (
                collection.get(
                    "redirects",
                    []
                )
            ),
        }


        pages.append(
            page
        )


        # ----------------------------------------------------
        # SEULEMENT HTML POUR LA DÉCOUVERTE
        # ----------------------------------------------------

        if (
            "text/html"
            not in content_type.lower()
            and content_type
        ):

            continue


        # ----------------------------------------------------
        # PROFONDEUR MAX ATTEINTE
        # ----------------------------------------------------

        if depth >= max_depth:

            continue


        # ----------------------------------------------------
        # EXTRACTION DES LIENS
        # ----------------------------------------------------

        links = extract_links(
            html=response.text,
            base_url=final_url,
        )


        for link in links:

            discovered_urls.add(
                link
            )


            # -----------------------------------------------
            # HORS SCOPE
            # -----------------------------------------------

            if not is_domain_allowed(
                link,
                allowed_domains,
            ):

                skipped.append(
                    {
                        "url": link,
                        "reason": "OUT_OF_SCOPE",
                    }
                )

                continue


            # -----------------------------------------------
            # ACTION EXCLUE
            # -----------------------------------------------

            if should_exclude_url(
                link
            ):

                skipped.append(
                    {
                        "url": link,
                        "reason": "EXCLUDED_ACTION",
                    }
                )

                continue


            # -----------------------------------------------
            # DÉDOUBLONNAGE
            # -----------------------------------------------

            if (
                link in visited_urls
                or link in queued_urls
            ):

                continue


            if (
                len(
                    visited_urls
                )
                + len(
                    queue
                )
                >= max_pages
            ):

                skipped.append(
                    {
                        "url": link,
                        "reason": "MAX_PAGES_REACHED",
                    }
                )

                continue


            queue.append(
                (
                    link,
                    depth + 1,
                )
            )

            queued_urls.add(
                link
            )


        # ----------------------------------------------------
        # RATE LIMIT
        # ----------------------------------------------------

        if (
            delay_seconds > 0
            and queue
        ):

            time.sleep(
                delay_seconds
            )


    # ========================================================
    # FIN
    # ========================================================

    duration_seconds = (
        time.monotonic()
        - started_at
    )


    return {
        "pages": pages,
        "errors": errors,
        "skipped": skipped,
        "request_count": request_count,
        "visited_count": len(
            visited_urls
        ),
        "discovered_count": len(
            discovered_urls
        ),
        "duration_seconds": round(
            duration_seconds,
            3,
        ),
    }