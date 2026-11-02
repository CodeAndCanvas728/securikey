"""`skey migrate`: copy the secrets from the keychain item the plugin used before 3.0.0 to the current one.

Values are compared in memory and never printed; only names and counts are.
"""
import hmac

from securikey.store import NAME_RE, VaultError


def _same(a, b):
    return hmac.compare_digest(a.encode(), b.encode())


def _plan(old_items, new_items):
    """(to_copy, unchanged, conflicts), as sorted name lists."""
    copy, unchanged, conflicts = [], [], []
    for name in sorted(old_items):
        if name not in new_items:
            copy.append(name)
        elif _same(old_items[name], new_items[name]):
            unchanged.append(name)
        else:
            conflicts.append(name)
    return copy, unchanged, conflicts


def needs_migration(new, old):
    """Whether the new store is empty and the old one holds secrets. Never raises: it only feeds a hint."""
    try:
        return not new.load() and bool(old.load())
    except VaultError:
        return False


def migrate(new, old, dry_run=False, purge_old=False, out=print):
    """Copy old -> new. Returns the exit code: 0 done, 1 when a name differs in the new store.

    Held under both stores' locks. Nothing already in the new store is overwritten, and the
    old item is deleted only after every name has been read back from the new store and
    compared, and only when nothing conflicts.
    """
    if new.service == old.service:
        raise VaultError("the old and new keychain service are both %r; nothing to migrate" % new.service)
    with new.transaction(), old.transaction():
        old_items, new_items = old.load(), new.load()
        if not old_items:
            out("nothing to migrate: the old keychain item (service %s) holds no secrets" % old.service)
            return 0
        bad = [n for n, v in old_items.items() if not NAME_RE.match(n) or not isinstance(v, str)]
        if bad:
            # Names are not echoed: an entry that is not a name may be a value.
            raise VaultError("the old keychain item has %d entr%s that %s not a valid name and text value; "
                             "nothing was changed" % (len(bad), "y" if len(bad) == 1 else "ies",
                                                      "is" if len(bad) == 1 else "are"))
        copy, unchanged, conflicts = _plan(old_items, new_items)
        verb = "would copy" if dry_run else "copied"
        for name in copy:
            out("%s %s" % (verb, name))
        for name in unchanged:
            out("already present, identical: %s" % name)
        for name in conflicts:
            out("differs from the new store, not overwritten: %s" % name)
        if conflicts:
            out("%d name(s) hold a different value in the new store. To take the old value, run "
                "`skey rm <name>` and then `skey migrate` again; to keep the new one, leave it. "
                "The old item is kept while any name differs." % len(conflicts))
        if not dry_run and copy:
            new.save({**new_items, **{n: old_items[n] for n in copy}})
            written = new.load()
            failed = [n for n in copy if n not in written or not _same(written[n], old_items[n])]
            if failed:
                raise VaultError("verification failed for %d name(s) after copying (%s); the old item "
                                 "was not touched" % (len(failed), ", ".join(failed)))
        out("%s %d, already present %d, differing %d" % ("would copy" if dry_run else "copied",
                                                         len(copy), len(unchanged), len(conflicts)))
        if purge_old:
            if conflicts:
                out("old item kept: resolve the differing name(s) first")
            elif dry_run:
                out("would delete the old keychain item (service %s) after verifying" % old.service)
            else:
                old.delete()
                out("deleted the old keychain item (service %s) after verifying every name" % old.service)
        elif not dry_run and not conflicts:
            out("the old item (service %s) was left in place; `skey migrate --purge-old` deletes it "
                "once you have checked" % old.service)
    return 1 if conflicts else 0
