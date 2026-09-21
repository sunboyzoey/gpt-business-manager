"""Closed registration error evidence from trusted authentication responses."""
from urllib.parse import urlsplit


def registration_error_code(response) -> str:
    """Never classify prose, redirect destinations or arbitrary exception text."""
    try:
        status = response.status_code
        url = urlsplit(str(response.url))
        if (type(status) is not int or not 400 <= status <= 599
                or url.scheme != "https" or url.hostname not in {"auth.openai.com", "auth0.openai.com"}
                or url.port not in {None, 443} or url.username is not None or url.password is not None
                or url.path not in {"/api/accounts/user/register", "/api/accounts/create_account"}):
            return ""
        body = response.json()
        error = body.get("error") if type(body) is dict else None
        if type(error) is dict and error.get("code") == "user_already_exists":
            return "user_already_exists"
    except Exception:
        pass
    return ""
