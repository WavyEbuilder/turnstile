#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <climits>
#include <cerrno>

#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#include "turnstiled.hh"

#ifdef HAVE_SELINUX
#include <selinux/label.h>
#include <selinux/selinux.h>
#endif

int dir_make_at(int dfd, char const *dname, mode_t mode) {
    int sdfd = openat(dfd, dname, O_RDONLY | O_NOFOLLOW);
    struct stat st;
    int reterr = 0;
    int omask = umask(0);

#ifdef HAVE_SELINUX
    // We can't rely on policy transitions to set the user field of the context
    // correctly as that depends on the seuser db, so calculate the context to
    // create the runtimedir with ourselves.
    char *path = nullptr;
    char *context = nullptr;
    {
        // 10 for digits of an int, 1 for nullterm.
        char procfd[strlen("/proc/self/fd/") + 10 + 1];
        ssize_t len;
        snprintf(procfd, sizeof(procfd), "/proc/self/fd/%d", dfd);
        char dfd_path[PATH_MAX];
        len = readlink(procfd, dfd_path, sizeof(dfd_path)-1);
        if (len < 0) {
            goto ret_err;
        }
        dfd_path[len] = '\0';
        path = (char *)malloc(strlen(dfd_path) + 1 + strlen(dname) + 2);
        if (!path) {
            goto ret_err;
        }
        sprintf(path, "%s/%s", dfd_path, dname);

        struct selabel_handle *sehandle =
            selabel_open(SELABEL_CTX_FILE, nullptr, 0);
        if (!sehandle) {
            perror("selabel_open");
            goto ret_err;
        }
        if (selabel_lookup_raw(sehandle, &context, path, mode) < 0) {
            perror("selabel_lookup_raw");
            selabel_close(sehandle);
            goto ret_err;
        }
        selabel_close(sehandle);
        if (setfscreatecon_raw(context) < 0) {
            perror("setfscreatecon_raw");
            goto ret_err;
        }
    }
#endif

    if (fstat(sdfd, &st) || !S_ISDIR(st.st_mode)) {
        close(sdfd);
        if (mkdirat(dfd, dname, mode)) {
            goto ret_err;
        }
        sdfd = openat(dfd, dname, O_RDONLY | O_NOFOLLOW);
        if ((sdfd < 0) || (fstat(sdfd, &st) < 0)) {
            goto ret_err;
        }
        if (!S_ISDIR(st.st_mode)) {
            reterr = ENOTDIR;
            goto ret_err;
        }
    } else {
        /* dir_clear_contents closes the descriptor, we need to keep it */
        int nfd;
        if ((fchmod(sdfd, mode) < 0) || ((nfd = dup(sdfd)) < 0)) {
            goto ret_err;
        }

#ifdef HAVE_SELINUX
        if (lsetfilecon(path, context) < 0) {
            perror("lsetfilecon");
            goto ret_err;
        }
#endif

        if (!dir_clear_contents(nfd)) {
            reterr = ENOTEMPTY;
            goto ret_err;
        }
    }

#ifdef HAVE_SELINUX
    // Reset fs creation context so new objects are labelled correctly.
    if (setfscreatecon(nullptr) < 0) {
        perror("setfscreatecon");
        goto ret_err;
    }
    if (context) {
        free(context);
    }
    if (path) {
        free(path);
    }
#endif

    umask(omask);
    return sdfd;

ret_err:
#ifdef HAVE_SELINUX
    if (setfscreatecon(nullptr) < 0) {
        perror("setfscreatecon");
    }
    if (context) {
        free(context);
    }
    if (path) {
        free(path);
    }
#endif
    umask(omask);
    if (sdfd >= 0) {
        close(sdfd);
    }
    if (reterr) {
        errno = reterr;
    }
    return -1;
}

bool rundir_make(char *rundir, unsigned int uid, unsigned int gid) {
    struct stat dstat;
    int bfd = open("/", O_RDONLY | O_NOFOLLOW);
    if (bfd < 0) {
        print_err("rundir: failed to open root (%s)", strerror(errno));
        return false;
    }
    char *dirbase = rundir + 1;
    char *sl = std::strchr(dirbase, '/');
    print_dbg("rundir: make directory %s", rundir);
    /* recursively create all parent paths */
    mode_t omask = umask(022);
    while (sl) {
        *sl = '\0';
        print_dbg("rundir: try make parent %s", rundir);
        int cfd = openat(bfd, dirbase, O_RDONLY | O_NOFOLLOW);
        if (cfd < 0) {
            if (mkdirat(bfd, dirbase, 0755) == 0) {
                cfd = openat(bfd, dirbase, O_RDONLY | O_NOFOLLOW);
            }
        }
        if (cfd < 0 || fstat(cfd, &dstat) < 0) {
            print_err(
                "rundir: failed to make parent %s (%s)",
                rundir, strerror(errno)
            );
            close(bfd);
            close(cfd);
            umask(omask);
            return false;
        }
        if (!S_ISDIR(dstat.st_mode)) {
            print_err("rundir: non-directory encountered at %s", rundir);
            close(bfd);
            close(cfd);
            umask(omask);
            return false;
        }
        close(bfd);
        bfd = cfd;
        *sl = '/';
        dirbase = sl + 1;
        sl = std::strchr(dirbase, '/');
    }
    umask(omask);

#ifdef HAVE_SELINUX
    // We can't rely on policy transitions to set the user field of the context
    // correctly as that depends on the seuser db, so calculate the context to
    // create the runtimedir with ourselves.
    char *context = nullptr;
    {
        struct selabel_handle *sehandle =
            selabel_open(SELABEL_CTX_FILE, nullptr, 0);
        if (!sehandle) {
            print_err(
                "rundir: failed to make rundir %s (%s)",
                rundir, strerror(errno)
            );
            close(bfd);
            return false;
        }
        if (selabel_lookup_raw(sehandle, &context, rundir, 0700) < 0) {
            print_err(
                "rundir: failed to make rundir %s (%s)",
                rundir, strerror(errno)
            );
            selabel_close(sehandle);
            close(bfd);
            return false;
        }
        selabel_close(sehandle);
        if (setfscreatecon_raw(context) < 0) {
            print_err(
                "rundir: failed to make rundir %s (%s)",
                rundir, strerror(errno)
            );
            close(bfd);
            return false;
        }
    }
#endif

    /* now create rundir or at least sanitize its perms */
    if (
        (fstatat(bfd, dirbase, &dstat, AT_SYMLINK_NOFOLLOW) < 0) ||
        !S_ISDIR(dstat.st_mode)
    ) {
        if (mkdirat(bfd, dirbase, 0700) < 0) {
            print_err(
                "rundir: failed to make rundir %s (%s)",
                rundir, strerror(errno)
            );
            close(bfd);
            return false;
        }
    } else {
        if (fchmodat(bfd, dirbase, 0700, AT_SYMLINK_NOFOLLOW) < 0) {
            print_err("rundir: fchmodat failed for rundir (%s)", strerror(errno));
            close(bfd);
            return false;
        }
#ifdef HAVE_SELINUX
        if (lsetfilecon(rundir, context) < 0) {
            perror("lsetfilecon");
            close(bfd);
            return false;
        }
#endif
    }

#ifdef HAVE_SELINUX
    // Reset fs creation context so new objects are labelled correctly.
    if (setfscreatecon(nullptr) < 0) {
        perror("setfscreatecon");
        close(bfd);
        free(context);
        return false;
    }
    if (context) {
        free(context);
    }
#endif

    if (fchownat(bfd, dirbase, uid, gid, AT_SYMLINK_NOFOLLOW) < 0) {
        print_err("rundir: fchownat failed for rundir (%s)", strerror(errno));
        close(bfd);
        return false;
    }
    close(bfd);
    return true;
}

void rundir_clear(char const *rundir) {
    struct stat dstat;
    print_dbg("rundir: clear directory %s", rundir);
    int dfd = open(rundir, O_RDONLY | O_NOFOLLOW);
    /* non-existent */
    if (dfd < 0) {
        return;
    }
    /* an error? */
    if (fstat(dfd, &dstat)) {
        print_dbg("rundir: could not stat %s (%s)", rundir, strerror(errno));
        close(dfd);
        return;
    }
    /* not a directory */
    if (!S_ISDIR(dstat.st_mode)) {
        print_dbg("rundir: %s is not a directory", rundir);
        close(dfd);
        return;
    }
    if (dir_clear_contents(dfd)) {
        /* was empty */
        rmdir(rundir);
    } else {
        print_dbg("rundir: failed to clear contents of %s", rundir);
    }
}

bool dir_clear_contents(int dfd) {
    if (dfd < 0) {
        /* silently return if an invalid file descriptor */
        return false;
    }
    DIR *d = fdopendir(dfd);
    if (!d) {
        print_err("dir_clear: fdopendir failed (%s)", strerror(errno));
        close(dfd);
        return false;
    }

    unsigned char buf[offsetof(struct dirent, d_name) + NAME_MAX + 1];
    unsigned char *bufp = buf;

    struct dirent *dentb = nullptr, *dent = nullptr;
    std::memcpy(&dentb, &bufp, sizeof(dent));

    for (;;) {
        if (readdir_r(d, dentb, &dent) < 0) {
            print_err("dir_clear: readdir_r failed (%s)", strerror(errno));
            closedir(d);
            return false;
        }
        if (!dent) {
            break;
        }
        if (
            !std::strcmp(dent->d_name, ".") ||
            !std::strcmp(dent->d_name, "..")
        ) {
            continue;
        }

        print_dbg("dir_clear: clear %s at %d", dent->d_name, dfd);
        int efd = openat(dfd, dent->d_name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
        int ufl = 0;

        if (efd < 0) {
            /* this may fail e.g. for invalid sockets, we don't care */
            goto do_unlink;
        }

        struct stat st;
        if (fstat(efd, &st) < 0) {
            print_err("dir_clear: fstat failed (%s)", strerror(errno));
            closedir(d);
            return false;
        }

        if (S_ISDIR(st.st_mode)) {
            if (!dir_clear_contents(efd)) {
                closedir(d);
                return false;
            }
            ufl = AT_REMOVEDIR;
        } else {
            close(efd);
        }

do_unlink:
        if (unlinkat(dfd, dent->d_name, ufl) < 0) {
            print_err("dir_clear: unlinkat failed (%s)", strerror(errno));
            closedir(d);
            return false;
        }
    }

    closedir(d);
    return true;
}
