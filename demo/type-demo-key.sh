#!/bin/bash
# type-demo-key.sh SESSION
#
# Types a freshly generated, throwaway Stripe-test-shaped key into secret-box's
# masked box in a `movie term` session, then presses Enter. The key is made
# here at run time (sk_test_ + 24 random alphanumerics), is never printed, and
# is never written to a file: it reaches only the box, which saves it to the
# Keychain. scan-for-leaks.sh later reads it back from the Keychain to check
# that no recording holds it, and cleanup.sh deletes the item.
set -u
session=${1:?usage: type-demo-key.sh SESSION}
movie=${MOVIE:-/Users/david/.claude/plugins/cache/proving-it-works/proving-it-works/0.2.0/skills/proving-it-works-with-a-movie/bin/movie}

key=$(/usr/bin/python3 -c 'import secrets, string; a = string.ascii_letters + string.digits; print("sk_test_" + "".join(secrets.choice(a) for _ in range(24)))')
[ ${#key} -eq 32 ] || { echo "type-demo-key: generated key has the wrong length" >&2; exit 2; }

"$movie" term type "$session" "$key" >/dev/null 2>&1
typed=$?
unset key
echo "type-demo-key: typed a 32-character throwaway key (exit $typed)"
exit "$typed"
