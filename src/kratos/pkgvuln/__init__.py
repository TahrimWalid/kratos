"""Package-based vulnerabilities (phase A.2).

Kratos reads each machine's installed packages (``kratos.adapters.packages``, a
collection check) and matches them on the Kratos machine, offline, against the
distribution's own advisory data from OSV, so a fix a distribution backported
without changing the upstream version is not reported. CISA's Known Exploited
Vulnerabilities catalogue (KEV), FIRST's EPSS scores and NVD's CVSS scores order
the result.

- ``ecosystems`` -- which OSV data describes a machine (from /etc/os-release);
- ``versions``   -- version comparison (the ``univers`` library);
- ``index``      -- the local vulnerability index (``data_dir/vulndb/vulndb.sqlite``);
- ``update``     -- ``kratos vulndb-update``: download, build, swap atomically;
- ``match``      -- installed packages against the index (pure);
- ``priority``   -- KEV / EPSS / CVSS -> severity;
- ``inventory_store`` -- the ``pkg_inventory`` table in kratos.db;
- ``record`` / ``check`` -- the ``packages`` collection check;
- ``crosscheck`` -- marks network CVE matches the distribution already fixed.

The package list never leaves Kratos: investigations make no network request for
vulnerability data, and ``kratos vulndb-update`` downloads whole exports.
"""
