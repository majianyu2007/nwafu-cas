"""Fixed facts about authserver.nwafu.edu.cn (金智 AuthServer 3.8.x)."""

AUTH_SERVER = "https://authserver.nwafu.edu.cn"
BASE = f"{AUTH_SERVER}/authserver"

# The new portal; any campus service works, this one is always available.
DEFAULT_SERVICE = "https://ehall.nwafu.edu.cn/login"

UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/150.0 Safari/537.36"
)

TGC_COOKIE = "CASTGC"
# Set by /authserver/bfp/info; "信任此设备" is recorded against its value.
TRUSTED_DEVICE_COOKIE = "MULTIFACTOR_BROWSER_FINGERPRINT"

# Redirects are only followed inside the university.
CAMPUS_HOST_SUFFIXES = (".nwafu.edu.cn", ".nwsuaf.edu.cn")

# Theme asset version (``?v=`` on the login page scripts) this release was
# checked against. `nwafu-cas doctor` reports when the live site differs.
VERIFIED_THEME = "20260922.133736"
VERIFIED_ON = "2026-10-25"
