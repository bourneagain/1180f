/* CVE-2017-15118
     ref. https://bugzilla.redhat.com/attachment.cgi?id=1358264&action=diff
     
   a qemu client can send a request to the Network Block Device (NBD) qemu server:
     $ qemu-io f raw nbd://localhost:10809/path
*/

#define NBD_MAX_NAME_SIZE 256

static int nbd_negotiate_handle_info(NBDClient *client, uint32_t length,
                                     uint32_t opt, uint16_t myflags,
                                     Error **errp) {
    char name[NBD_MAX_NAME_SIZE + 1];
    uint16_t requests;
    uint32_t namelen;
    const char *msg;

    /* Client sends:
        4 bytes: L, name length (can be 0)
        L bytes: export name
        2 bytes: N, number of requests (can be 0)
        N * 2 bytes: N requests
    */
    if (length < sizeof(namelen) + sizeof(requests)) {
        msg = "overall request too short";
        goto invalid;
    }
    if (nbd_read(client->ioc, &namelen, sizeof(namelen), errp) < 0) {
        return -EIO;
    }

    be32_to_cpus(&namelen);
    length -= sizeof(namelen);
    if (namelen > length - sizeof(requests) || (length - namelen) % 2) {
        msg = "name length is incorrect";
        goto invalid;
    }
    if (nbd_read(client->ioc, name, namelen, errp) < 0) {
        return -EIO;
    }
    name[namelen] = '\0';
    ...
}

/* nbd_read
 * Reads @size bytes from @ioc. Returns 0 on success. */
static inline int nbd_read(QIOChannel *ioc, void *buffer, size_t size,
                           Error **errp);
