# Test wordlists — TEST-ONLY, not real-world attack material

`weak_test_passwords_20.txt` is a short, curated list of ~20 widely-known weak/default
passwords (things like `password`, `123456`, `admin`, plus `ubuntu` matching this project's
dev-target username, as a realistic "reused the username as the password" case). It is
deliberately small.

This is **not** a real breach/leak wordlist (no rockyou.txt, no scraped credential dumps) and
is not intended to crack anything beyond a deliberately-weak test target. Do not replace it
with a large real-world wordlist without a clear reason tied to an authorized test.
