# ==================================================
# OCT 2026 STEP 23: CENTRAL i18n (Hebrew / English)
# ==================================================
#
# Single place that owns: language selection, the Flask-Babel instance,
# the language-switch route, and the technical-value LTR-isolation
# helper. No other module should read/write the language cookie/session
# key directly - everything goes through get_locale()/the /set-language
# route here, so there is exactly one source of truth for "what language
# is this request in".
#
# HARD GUARANTEE: this module NEVER touches detection/scoring/alert/
# response code and NEVER changes a stored database value. It only
# affects how ALREADY-COMPUTED values are PRESENTED - translation is a
# rendering concern, applied in templates via {{ _('...') }} and in
# Python via gettext's _(...), never by rewriting what gets written to a
# row. Internal values (DB columns, status codes like 'NEW'/'OPEN',
# event/alert ids, field names used by business logic) are never passed
# through translation - only their DISPLAY mapping is (see
# templates' use of severity/status display helpers).
# ==================================================

import os

from flask import (
    Blueprint,
    request,
    redirect,
    session,
    make_response
)
from flask_babel import Babel, gettext as _  # noqa: F401 (re-exported for convenience)
from markupsafe import Markup, escape

SUPPORTED_LANGUAGES = {"he": "עברית", "en": "English"}

# Default language for a fresh installation - explicit requirement:
# Israeli deployments default to Hebrew. Overridable (e.g. for a
# non-Israeli deployment) via DEFAULT_LANGUAGE in .env - never hardcoded
# as the only option.
DEFAULT_LANGUAGE = os.getenv("DEFAULT_LANGUAGE", "he").strip().lower()
if DEFAULT_LANGUAGE not in SUPPORTED_LANGUAGES:
    DEFAULT_LANGUAGE = "he"

LANGUAGE_COOKIE_NAME = "soc_lang"
LANGUAGE_COOKIE_MAX_AGE = 60 * 60 * 24 * 365  # 1 year - a real, named persistence choice

RTL_LANGUAGES = {"he"}


def get_locale():

    # Priority, in this exact order:
    #   1. An explicit choice THIS session already made (set by
    #      /set-language) - a deliberate in-session override always wins.
    #   2. A returning browser's saved cookie (persists across logins/
    #      restarts of the browser, not just the Flask session).
    #   3. The installation's own default (DEFAULT_LANGUAGE).
    # Deliberately never guesses from the browser's Accept-Language
    # header - behavior stays predictable and auditable: a user who has
    # never chosen or been given a cookie always lands on the
    # installation's documented default.
    lang = session.get("lang")
    if lang in SUPPORTED_LANGUAGES:
        return lang

    lang = request.cookies.get(LANGUAGE_COOKIE_NAME)
    if lang in SUPPORTED_LANGUAGES:
        return lang

    return DEFAULT_LANGUAGE


def is_rtl(lang=None):

    return (lang or get_locale()) in RTL_LANGUAGES


def ltr_wrap(value):

    # Technical values (IP addresses, URLs, file names, hashes, command
    # names, ids) must display left-to-right and never have their
    # characters reordered or mixed with surrounding Hebrew text - this
    # is the HTML-standard tool for exactly that: <bdi> isolates the
    # element's content from the surrounding paragraph's bidi context,
    # and dir="ltr" additionally forces the correct direction for
    # content that is always LTR by nature (an IP/URL/hash is never
    # itself written right-to-left). Used as a Jinja filter: {{ ip|ltr }}.
    if value is None or value == "":
        return ""
    return Markup(f'<bdi dir="ltr">{escape(value)}</bdi>')


def severity_label(code):

    # Maps the INTERNAL severity code (INFO/LOW/MEDIUM/HIGH/CRITICAL -
    # the exact value stored in security_alerts.severity/security_events
    # .severity and used everywhere in business logic, CSS class names,
    # and SQL) to a translatable DISPLAY string. The stored value itself
    # is never touched - only this presentation-layer mapping is
    # translated. Each branch below is a literal _("...") call so
    # `pybabel extract` can find it statically; an unrecognized code is
    # shown as-is rather than silently hidden.
    mapping = {
        "CRITICAL": _("Critical"),
        "HIGH": _("High"),
        "MEDIUM": _("Medium"),
        "LOW": _("Low"),
        "INFO": _("Info"),
    }
    return mapping.get((code or "").upper(), code)


babel = Babel()


def init_babel(app):

    # Flask-Babel registers _()/gettext()/ngettext() as Jinja globals on
    # its own (configure_jinja=True, the default) - no extra wiring
    # needed for that part.
    babel.init_app(
        app,
        default_locale=DEFAULT_LANGUAGE,
        default_translation_directories="translations",
        locale_selector=get_locale
    )

    # Exposed to every template with no per-template import needed -
    # matches the existing project convention (compute_endpoint_presence
    # and friends are already imported once into app.py and used
    # everywhere; here the equivalent is a Jinja global/filter instead,
    # since these are called FROM templates, not from route code).
    app.jinja_env.globals["get_locale"] = get_locale
    app.jinja_env.globals["is_rtl"] = is_rtl
    app.jinja_env.globals["SUPPORTED_LANGUAGES"] = SUPPORTED_LANGUAGES
    app.jinja_env.globals["severity_label"] = severity_label
    app.jinja_env.filters["ltr"] = ltr_wrap


i18n_bp = Blueprint("i18n", __name__)


def _safe_redirect_target(candidate):

    # Only ever redirect back to a path INSIDE this app (never to an
    # attacker-supplied external host) - defends the "return to where
    # you were, with your filters/query string intact" behavior against
    # open-redirect misuse.
    if not candidate:
        return "/"

    try:
        from urllib.parse import urlparse

        parsed = urlparse(candidate)

        if parsed.netloc and parsed.netloc != request.host:
            return "/"

        path = parsed.path or "/"
        if not path.startswith("/"):
            return "/"

        if parsed.query:
            path = f"{path}?{parsed.query}"

        return path

    except Exception:
        return "/"


@i18n_bp.route("/set-language/<lang_code>")
def set_language(lang_code):

    # Deliberately has no login_required() gate - the language switch is
    # meaningful even on the (unauthenticated) login page itself, and it
    # never exposes or changes anything session/permission-related
    # beyond the language key.
    lang_code = lang_code.strip().lower()
    if lang_code not in SUPPORTED_LANGUAGES:
        lang_code = DEFAULT_LANGUAGE

    session["lang"] = lang_code

    # "next" (the exact current path+query string, passed explicitly by
    # the template link) is preferred over request.referrer, which some
    # browsers/privacy settings omit or rewrite - this is what makes the
    # switch preserve the current page AND its existing filters.
    target = _safe_redirect_target(request.args.get("next") or request.referrer)

    response = make_response(redirect(target))
    response.set_cookie(
        LANGUAGE_COOKIE_NAME,
        lang_code,
        max_age=LANGUAGE_COOKIE_MAX_AGE,
        httponly=True,
        samesite="Lax",
        # Secure only when the request itself arrived over HTTPS - set
        # unconditionally True would silently break the cookie on this
        # project's current plain-HTTP local dev setup (README's
        # documented MODE 1); a production HTTPS deployment (MODE 2,
        # per the Phase 14C transport design) automatically gets the
        # secure flag with no code change, since request.is_secure
        # reflects the real connection.
        secure=request.is_secure,
    )
    return response
