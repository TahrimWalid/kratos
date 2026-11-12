"""E.3: what is normal per machine, learned by counting the history Kratos already stores.

A closed set of dimensions (sign-in source, time and method; sudo use; listeners; outbound
peers; program starts where auditd records them), each a decayed count per key with first
and last seen. First-time and rare things become BASE-* findings that show the usual
pattern beside the new thing. Learning counts covered history only, holds back events near
an open serious finding, never learns Kratos's own activity, and a deviation alone is
never above medium. A baseline never lowers, hides or closes any other finding.
"""
