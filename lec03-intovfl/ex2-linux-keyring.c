/* CVE-2016-0728
   ref. Linux, @23567fd052a9abb6d67fe8e7a9ccdd9800a540f2 */

/* Join the named keyring as the session keyring if possible else
 * attempt to create a new one of that name and join that. */
long join_session_keyring(const char *name) {
  struct cred *new = prepare_creds();
  ...
  
  /* allow the user to join or create a named keyring */
  mutex_lock(&key_session_mutex);

  /* look for an existing keyring of this name */
  keyring = find_keyring_by_name(name, false);
  if (PTR_ERR(keyring) == -ENOKEY) {
    /* not found - try and create a new one */
    keyring = keyring_alloc(
      name, old->uid, old->gid, old,
      KEY_POS_ALL | KEY_USR_VIEW | KEY_USR_READ | KEY_USR_LINK,
      KEY_ALLOC_IN_QUOTA, NULL);
    if (IS_ERR(keyring)) {
      ret = PTR_ERR(keyring);
      goto error2;
    }
  } else if (IS_ERR(keyring)) {
    ret = PTR_ERR(keyring);
    goto error2;
  } else if (keyring == new->session_keyring) {
    ret = 0;
    goto error2;
  }

  /* we've got a keyring - now to install it */
  ret = install_session_keyring_to_cred(new, keyring);
  if (ret < 0)
    goto error2;

  commit_creds(new);
  mutex_unlock(&key_session_mutex);

  ret = keyring->serial;
  key_put(keyring);
okay:
  return ret;

error2:
  mutex_unlock(&key_session_mutex);
error:
  abort_creds(new);
  return ret;
}

/* Find a keyring with the specified name.
 * ...
 * Returns a pointer to the keyring with the keyring's refcount having being
 * incremented on success.  -ENOKEY is returned if a key could not be found. */
struct key *find_keyring_by_name(const char *name, bool skip_perm_check) { ... }