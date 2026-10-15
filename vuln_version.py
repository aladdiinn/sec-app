import re

def split_debian_version(v: str):
    """Split Debian version into (epoch, upstream_version, debian_revision)."""
    epoch = 0
    if ":" in v:
        ep_str, rest = v.split(":", 1)
        try: epoch = int(ep_str)
        except ValueError: epoch = 0
    else:
        rest = v
    if "-" in rest:
        upstream, revision = rest.rsplit("-", 1)
    else:
        upstream = rest
        revision = ""
    return epoch, upstream, revision

def _order_deb_char(c: str) -> int:
    if not c: return 0
    if c == "~": return -1
    if c.isdigit(): return 1
    if c.isalpha(): return ord(c)
    return ord(c) + 256

def _compare_deb_part(s1: str, s2: str) -> int:
    i1, i2 = 0, 0
    n1, n2 = len(s1), len(s2)
    while i1 < n1 or i2 < n2:
        # Compare non-digit characters
        while (i1 < n1 and not s1[i1].isdigit()) or (i2 < n2 and not s2[i2].isdigit()):
            c1 = s1[i1] if i1 < n1 else ""
            c2 = s2[i2] if i2 < n2 else ""
            if c1 != c2:
                o1 = _order_deb_char(c1)
                o2 = _order_deb_char(c2)
                if o1 < o2: return -1
                if o1 > o2: return 1
            if i1 < n1: i1 += 1
            if i2 < n2: i2 += 1

        # Compare digit sequences numerically
        num1_start = i1
        while i1 < n1 and s1[i1].isdigit(): i1 += 1
        num2_start = i2
        while i2 < n2 and s2[i2].isdigit(): i2 += 1
        val1 = int(s1[num1_start:i1]) if i1 > num1_start else 0
        val2 = int(s2[num2_start:i2]) if i2 > num2_start else 0
        if val1 < val2: return -1
        if val1 > val2: return 1
    return 0

def compare_debian_versions(v1: str, v2: str) -> int:
    """
    Compare two Debian/Ubuntu package version strings per Debian policy 5.6.12.
    Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
    """
    if not v1 and not v2: return 0
    if not v1: return -1
    if not v2: return 1
    if v1 == v2: return 0

    ep1, up1, rev1 = split_debian_version(v1)
    ep2, up2, rev2 = split_debian_version(v2)

    if ep1 < ep2: return -1
    if ep1 > ep2: return 1

    cmp_up = _compare_deb_part(up1, up2)
    if cmp_up != 0: return cmp_up

    return _compare_deb_part(rev1, rev2)


def split_rpm_version(v: str):
    """Split RPM version into (epoch, version, release)."""
    epoch = 0
    if ":" in v:
        ep_str, rest = v.split(":", 1)
        try: epoch = int(ep_str)
        except ValueError: epoch = 0
    else:
        rest = v
    if "-" in rest:
        version, release = rest.rsplit("-", 1)
    else:
        version = rest
        release = ""
    return epoch, version, release

def _compare_rpm_segments(s1: str, s2: str) -> int:
    # RPM comparison splits string into segments of alpha, digit, or separator
    chunks1 = re.findall(r'[0-9]+|[a-zA-Z]+|~', s1)
    chunks2 = re.findall(r'[0-9]+|[a-zA-Z]+|~', s2)
    for c1, c2 in zip(chunks1, chunks2):
        if c1 == c2: continue
        if c1 == '~': return -1
        if c2 == '~': return 1
        if c1.isdigit() and c2.isdigit():
            i1, i2 = int(c1), int(c2)
            if i1 < i2: return -1
            if i1 > i2: return 1
        elif c1.isdigit():
            return 1  # numbers are newer than letters
        elif c2.isdigit():
            return -1
        else:
            if c1 < c2: return -1
            if c1 > c2: return 1
    if len(chunks1) < len(chunks2):
        # If remaining chunks in chunks2 start with ~, s1 is newer
        if len(chunks2) > len(chunks1) and chunks2[len(chunks1)] == '~':
            return 1
        return -1
    if len(chunks1) > len(chunks2):
        if chunks1[len(chunks2)] == '~':
            return -1
        return 1
    return 0

def compare_rpm_versions(v1: str, v2: str) -> int:
    """
    Compare two RPM / RHEL / CentOS package version strings.
    Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
    """
    if not v1 and not v2: return 0
    if not v1: return -1
    if not v2: return 1
    if v1 == v2: return 0

    ep1, ver1, rel1 = split_rpm_version(v1)
    ep2, ver2, rel2 = split_rpm_version(v2)

    if ep1 < ep2: return -1
    if ep1 > ep2: return 1

    cmp_v = _compare_rpm_segments(ver1, ver2)
    if cmp_v != 0: return cmp_v

    return _compare_rpm_segments(rel1, rel2)


def compare_semver(v1: str, v2: str) -> int:
    """
    General version comparison for standalone software (Tomcat, Java, PostgreSQL).
    Extracts numeric parts and compares tuple of ints.
    """
    if not v1 and not v2: return 0
    if not v1: return -1
    if not v2: return 1
    if v1 == v2: return 0

    def parse_parts(s):
        parts = []
        for x in re.split(r'[\.\-\_\+]', str(s).strip()):
            if x.isdigit():
                parts.append(int(x))
            else:
                m = re.match(r'^([0-9]+)([a-zA-Z]+.*)$', x)
                if m:
                    parts.append(int(m.group(1)))
                    parts.append(m.group(2))
                else:
                    parts.append(x)
        return parts

    p1 = parse_parts(v1)
    p2 = parse_parts(v2)
    for c1, c2 in zip(p1, p2):
        if c1 == c2: continue
        if isinstance(c1, int) and isinstance(c2, int):
            return -1 if c1 < c2 else 1
        elif isinstance(c1, int):
            return 1
        elif isinstance(c2, int):
            return -1
        else:
            return -1 if str(c1) < str(c2) else 1
    if len(p1) < len(p2): return -1
    if len(p1) > len(p2): return 1
    return 0


def is_package_vulnerable(installed_version: str, fixed_version: str, ecosystem: str = "Ubuntu") -> bool:
    """
    Determine whether installed_version is strictly older than fixed_version
    using distro-specific version comparison rules.
    If no fixed_version is provided (vulnerability without known fix), returns True
    if installed is affected.
    """
    if not installed_version:
        return False
    if not fixed_version or fixed_version.lower() in ("none", "unknown", "0", ""):
        # Advisory has no fix available yet
        return True

    eco = (ecosystem or "").lower()
    if "ubuntu" in eco or "debian" in eco:
        return compare_debian_versions(installed_version, fixed_version) < 0
    elif "rhel" in eco or "red hat" in eco or "rocky" in eco or "centos" in eco or "fedora" in eco:
        return compare_rpm_versions(installed_version, fixed_version) < 0
    else:
        # Fallback to semver / debian
        return compare_debian_versions(installed_version, fixed_version) < 0
