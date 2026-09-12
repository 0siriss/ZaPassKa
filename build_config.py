"""
build_config.py — values baked in at build time.

Kept empty in the repository. The release workflow rewrites this file from
repository secrets so official builds ship with a Google OAuth client. When
the values stay empty the app asks the user for their own client instead, and
everything else works the same.
"""

GOOGLE_CLIENT_ID     = ""
GOOGLE_CLIENT_SECRET = ""
