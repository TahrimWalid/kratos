"""Questions about a group of machines at once (D.2).

``groups`` -- named lists of machines; ``collect`` -- each machine collected in its own
pinned thread, bounded; ``digest`` -- what the model reads (one Kratos-written block per
machine); ``answer`` -- the one model call, the extra reads it may ask for, and each
machine's part checked against THAT machine's evidence only; ``record`` -- the run's
rows; ``run`` -- the front door every surface uses.
"""
