"""
ad_auth.py — Active Directory authentication via LDAP NTLM
"""
import socket
import ssl

from ldap3 import Server, Connection, ALL, Tls
from ldap3.core.exceptions import LDAPException

tls = Tls(
    validate=ssl.CERT_OPTIONAL,
    version=ssl.PROTOCOL_TLS_CLIENT,
    ca_certs_file=None
)

def check_dc_reachable(ad_server: str, timeout: float = 2.0) -> bool:
    """TCP probe to LDAP port to check DC reachability."""
    host = ad_server.replace("ldaps://", "").replace("ldap://", "").split(":")[0]
    port = 636 if "ldaps://" in ad_server else 389
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except (OSError, socket.timeout):
        return False


def authenticate(ad_server: str, username: str, password: str) -> bool:
    """Authenticate user against AD via NTLM bind. Returns True on success."""
    try:
        server = Server(ad_server, get_info=ALL, connect_timeout=5, use_ssl=True, tls=tls)
        conn = Connection(
            server,
            user=f"{username}@{ad_server}",
            password=password,
            auto_bind=True,
            receive_timeout=5
        )
        conn.unbind()
        return True
    except (LDAPException, Exception):
        return False
