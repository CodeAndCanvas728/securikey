---
harvested: true
---

# Which key does that service hold? Compare by hash

Use when a service rejects a key (403, "invalid key") and there are several
candidates it could expect: a legacy and a new key, two environments, a key
rotated in one place but not the other. No character of any candidate is
ever printed: only a 12-character hash prefix reaches the conversation.

## Steps

1. **Get the service's digest.** Some CLIs list secrets as names plus a
   digest instead of the value; `supabase secrets list` shows a SHA-256
   digest per secret. Check the digest really is a plain SHA-256 of the
   value before relying on it: hash a value that is not secret and is stored
   the same way (a project URL) and compare.

   ```bash
   printf '%s' 'https://<project>.example.co' | shasum -a 256 | cut -c1-12
   ```

2. **The user hashes each candidate**, preferably in their own terminal.
   They copy a candidate key from its dashboard and run:

   ```bash
   pbpaste | shasum -a 256 | cut -c1-12
   ```

   If they run it in this session with the `!` prefix instead, its output
   lands in the conversation outside the redaction hooks: the command must be
   exactly the line above, never `pbpaste` on its own. Never ask them to
   paste the key, and never read the clipboard yourself.

3. **Compare prefixes.** The candidate whose prefix equals the service's
   digest is the key it holds. A prefix that matches a *different* entry
   (the public key, say) means the clipboard held the wrong key: ask them to
   copy again.

4. **Which kind of key is it?** Do not print any of its characters. Test for
   a known type marker instead; this prints the marker or nothing:

   ```bash
   pbpaste | grep -oE '^(sb_secret_|sb_publishable_|eyJ)'
   ```

   `eyJ` is a JWT (a legacy Supabase key); extend the list with the markers
   of the provider at hand.

## A value stored in a database you can query

When the user has connected you to the database that holds the candidate
(a Postgres vault, say), compute the same prefix there and select nothing
else:

```sql
select left(encode(sha256(convert_to(decrypted_secret, 'utf8')), 'hex'), 12) as sha_prefix
from vault.decrypted_secrets where name = '<secret name>';
```

For a JWT, its role claim tells which key it is without exposing it; select
only the claim:

```sql
select (convert_from(decode(translate(p, '-_', '+/') || repeat('=', (4 - length(p) % 4) % 4), 'base64'), 'utf8')::json) ->> 'role' as role
from (select split_part(decrypted_secret, '.', 2) as p
      from vault.decrypted_secrets where name = '<secret name>') s;
```

**Verified:** 2026-11-17, Supabase project: the `SUPABASE_URL` digest from
`supabase secrets list` matched `printf '%s' <url> | shasum -a 256`; the key
in Vault hashed differently from `SUPABASE_SERVICE_ROLE_KEY`; the user's
copied `sb_secret_` key matched it; with that key stored the job answered
200 instead of 403.
**Failure pattern:** a service compares a caller's key to its own exactly,
and the key stored for the caller is a different (still valid-looking) key:
a 403 with no further detail.
**Ruled out:** reading the service's environment (not readable, and it would
reveal the value); trusting docs that said the legacy key was needed (the
service held the new one); assuming the user copied the intended key (the
first hash matched the public key instead).
