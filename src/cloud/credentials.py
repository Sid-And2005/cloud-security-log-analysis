"""Azure credentials.

On the VM, ``DefaultAzureCredential`` resolves to the user-assigned managed
identity selected by ``AZURE_CLIENT_ID``; on a developer laptop it falls back
to the Azure CLI login. No keys or secrets are stored by the application.
"""

import threading

from .. import config

# Scope for Microsoft Entra authentication to Azure Database for PostgreSQL.
POSTGRES_SCOPE = "https://ossrdbms-aad.database.windows.net/.default"

_lock = threading.Lock()
_credential = None


def get_credential():
    global _credential
    with _lock:
        if _credential is None:
            from azure.identity import DefaultAzureCredential

            _credential = DefaultAzureCredential(
                managed_identity_client_id=config.AZURE_CLIENT_ID,
                exclude_interactive_browser_credential=True,
            )
        return _credential


def postgres_access_token():
    """Short-lived Entra token used as the PostgreSQL password.

    azure-identity caches the token and refreshes it before expiry, so this is
    cheap to call for each new pooled connection.
    """
    return get_credential().get_token(POSTGRES_SCOPE).token
