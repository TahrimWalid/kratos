"""Attack paths (E.1): a read-free synthesis over stored evidence (D.2-E.7a) that draws a
graph of a group's machines, services, accounts, keys, privileges, containers and served
code, ranks entry points and the paths that reach the machines that matter, names the one
fix that cuts the most paths, and states what Kratos could not see as numbers.

Nothing here reads a machine, runs a model, or changes anything: a build reads ``kratos.db``
and the per-machine snapshot files and writes ``path_*`` rows and ``PATH-*`` findings. Paths
are recommendations only.

The user-facing name is "paths" (``/paths``, ``kratos paths``, ``path_*`` tables, ``paths.*``
settings, ``PATH-*`` findings, the ``attack_paths`` data category). The Python package is
named ``attackpaths`` only because ``kratos.paths`` is the core module that decides where
Kratos keeps its files -- see the E.1 Handoff.
"""
