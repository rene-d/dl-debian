#! /usr/bin/env python3
# vim:set ts=4 sw=4 et:

import sys
import os
import stat
import functools
import posixpath
import glob
import argparse
import urllib.parse
import tempfile
import codecs
import gzip
import sqlite3
import json
import time


# # lzma n'est pas toujours présent
# try:
#     import lzma
# except ImportError:
#     lzma = None
#     pass

# python 3 est requis
if sys.version_info.major < 3:
    raise "Must be using Python 3"

# # règle un problème de sortie vers un fichier
# if sys.stdout.encoding is None:
#     reload(sys)
#     sys.setdefaultencoding('utf-8')

# Variables globales
verbosity = 0

# fonction lambda pour afficher sur stderr
error = functools.partial(print, file=sys.stderr)


def debug(level: int, *args):
    """
        affiche un message de mise au point
        @param level niveau de détail
        @param args
    """
    if verbosity >= level:

        RED = "\033[91m"
        # GREEN = '\033[92m'
        YELLOW = "\033[93m"
        # LIGHT_PURPLE = '\033[94m'
        PURPLE = "\033[95m"
        END = "\033[0m"

        if level <= 1:
            sys.stderr.write(YELLOW)
        elif level == 2:
            sys.stderr.write(PURPLE)
        else:
            sys.stderr.write(RED)

        sys.stderr.write(" ".join(args))
        sys.stderr.write(END)
        sys.stderr.write("\n")


class mirror:
    def __init__(self, tmp_dir=".tmp"):
        self.active_catalog = []
        self._set_tmp_dir(tmp_dir)

        self.db = sqlite3.connect(os.path.join(self.tmp_dir, "mirror.db"))
        self.marker = os.path.join(self.tmp_dir, "pools.json")

        self.db.executescript("""\

create table if not exists catalog (
    catalog_id  integer not null primary key autoincrement,
    filename    text not null,
    timestamp   datetime,
    size        integer,
    done        boolean,
    count       integer
);

create table if not exists package (
    catalog_id  integer not null,
    filename    text not null,
    size        integer,
    hash        text
);

create table if not exists pool (
    filename    text not null,
    size        integer not null
);

create table if not exists pool_scanned (
    filename    text not null,
    timestamp   datetime not null
);

create index if not exists catalog_fk on package (filename);

create index if not exists package_fk on package (catalog_id);

""")

    def _set_tmp_dir(self, tmp_dir):
        if tmp_dir is None:
            self.tmp_dir = tempfile.mkdtemp(suffix="mirror", dir=tmp_dir)
        else:
            self.tmp_dir = tmp_dir
        os.makedirs(self.tmp_dir, exist_ok=True)
        assert os.path.isdir(self.tmp_dir)
        self.tmp_dir = os.path.abspath(self.tmp_dir)
        debug(1, "tmp-dir %s" % self.tmp_dir)

    def _is_key(a, b):
        return a.lower().startswith((b + ":").lower())

    def _get_val(a):
        return a[a.find(":") + 1 :].lstrip()

    def _packages(self, f, inserter, filename):
        """
        callback, analyse les fichiers Packages
        """
        debug(1, "Scanning _packages {}".format(filename))
        filename = ""
        size = None
        md5 = None
        nb = 0

        def reset():
            nonlocal self, filename, size, md5, nb
            filename = ""
            size = None
            md5 = None

        def finish():
            nonlocal self, filename, size, md5, nb
            if filename != "":
                inserter(filename, size, md5)
                nb += 1

        for i in f.readlines():
            i = i.decode("utf-8").rstrip()
            if i == "":
                finish()
                reset()
            elif mirror._is_key(i, "Filename"):
                filename = mirror._get_val(i)
            elif mirror._is_key(i, "Size"):
                size = int(mirror._get_val(i))
            elif mirror._is_key(i, "MD5sum"):
                md5 = mirror._get_val(i)

        finish()
        return nb

    def _sources(self, f, inserter, filename):
        """
        callback, analyse les fichiers Sources
        """
        debug(1, "Scanning _sources {}".format(filename))
        in_files = False
        directory = ""
        files = []
        nb = 0

        def reset():
            nonlocal self, in_files, directory, files, nb
            in_files = False
            directory = ""
            files = []

        def finish():
            nonlocal self, in_files, directory, files, nb
            if directory != "":
                for i in files:
                    inserter(os.path.join(directory, i[0]), int(i[1]), i[2])
                    nb += 1

        for i in f.readlines():
            i = i.decode("utf-8").rstrip()
            if i == "":
                finish()
                reset()
            if in_files:
                if i[0] == " " or i[0] == "\t":
                    i = i.lstrip().split(" ")
                    files.append((i[2], i[1], i[0]))  # name size md5/sha256
                else:
                    in_files = False
            if i == "Checksums-Sha256:":  # la section Files: contient la liste avec hash md5. dépréciée?
                in_files = True
            elif i[0:10] == "Directory:":
                directory = i[10:].lstrip()

        finish()
        return nb

    def _unwanted(self, filename):
        if filename.find("-armhf") != -1:
            return True
        if filename.find("-armel") != -1:
            return True
        if filename.find("-arm64") != -1:
            return True
        if filename.find("-hurd-i386") != -1:
            return True
        if filename.find("-kfreebsd") != -1:
            return True  # -kfreebsd-amd64 -kfreebsd-i386
        if filename.find("-mips") != -1:
            return True  # -mips -mips64el -mipsel
        if filename.find("-powerpc") != -1:
            return True
        if filename.find("-ppc64el") != -1:
            return True
        if filename.find("-s390x") != -1:
            return True
        return False

    def parse(self, filename, path):
        """
        lit un fichier ou une arborescence de fichiers Packages et Sources
        """

        mod = None
        func = None

        name, ext = os.path.splitext(os.path.basename(filename))

        if name == "Packages":
            func = self._packages
        elif name == "Sources":
            func = self._sources

        if ext == ".gz":
            mod = gzip
        # elif ext == ".xz":
        #     mod = lzma
        elif ext == "":
            mod = codecs

        if mod and func:
            orig = os.path.relpath(filename, path)
            with mod.open(filename, "rb") as f:
                if len(f.peek(1)) > 0:

                    if self._unwanted(filename):
                        debug(1, "File ignored: {}".format(orig))
                        return

                    st = os.stat(filename)

                    cur = self.db.cursor()
                    cur.execute(
                        "select catalog_id,timestamp,size,done from catalog where filename=?",
                        [filename],
                    )

                    row = cur.fetchone()

                    if row is not None and (
                        row[1] == st.st_mtime and row[2] == st.st_size and row[3] == 1
                    ):
                        # print("File {} already parsed".format(orig))
                        self.active_catalog.append(row[0])

                    else:
                        if row is not None:
                            cur.execute("delete from catalog where catalog_id=?", [row[0]])
                            cur.execute("delete from package where catalog_id=?", [row[0]])

                        cur.execute(
                            "insert into catalog (filename,timestamp,size,done) values (?,?,?,?)",
                            (filename, st.st_mtime, st.st_size, 0),
                        )
                        catalog_id = cur.lastrowid

                        # debug(2, "new catalog_id: " + str(catalog_id))
                        # sys.stdout.write("Reading {} …".format(orig))
                        # sys.stdout.flush()

                        nb = func(
                            f,
                            lambda filename, size, md5: cur.execute(
                                "insert into package values (?,?,?,?)",
                                (catalog_id, filename, size, md5),
                            ),
                            filename,
                        )

                        # sys.stdout.write(" found {} file(s)\n".format(nb))
                        debug(1, "{} entries added: {}".format(filename, nb))

                        cur.execute(
                            "update catalog set done=1,count=? where rowid=?", [nb, catalog_id]
                        )

                        self.active_catalog.append(catalog_id)

                    cur.close()
                    self.db.commit()

    def set_dists_db(self):
        cur = self.db.cursor()
        self.active_catalog = []
        for row in cur.execute("select distinct catalog_id from catalog"):
            self.active_catalog.append(row[0])
        cur.close()
        debug(1, "dists-db: {}".format(str(self.active_catalog)))

    def total(self):
        cur = self.db.cursor()
        cur.execute(
            "select sum(count) from catalog where catalog_id in ({})".format(
                ",".join([str(i) for i in self.active_catalog])
            )
        )
        nb1 = cur.fetchone()[0]
        cur.execute(
            "select count(distinct hash) from package where catalog_id in ({})".format(
                ",".join([str(i) for i in self.active_catalog])
            )
        )
        nb2 = cur.fetchone()[0]
        cur.close()
        print("Total: {} file(s), {} unique".format(nb1, nb2))

    def get_pool_marker(self):
        """
        retourne la date du dernier scan du pool ou la date courante
        """
        try:
            with open(self.marker, "r") as f:
                d = json.load(f)
        except FileNotFoundError:
            d = dict()
        t = d.get(self.pool, time.time())
        return t

    def set_pool_marker(self):
        """
        écrit la date courante pour le pool si absente
        """
        try:
            with open(self.marker, "r") as f:
                d = json.load(f)
        except FileNotFoundError:
            d = dict()
        t = d.get(self.pool, 0)
        if t == 0:
            t = time.time()
            d[self.pool] = t
            with open(self.marker, "w") as f:
                json.dump(d, f)
        return t

    def set_pool(self, pool, scandir=False):

        self.pool = pool
        self.pool_files = None

        if scandir:

            self.pool_files = dict()
            cur = self.db.cursor()

            can_load = False

            # le marker n'existe pas: on scan et on le crée
            # le marker existe:
            #   si sa date de modification est la même ou plus ancienne, on charge
            #   si sa date de modification est plus récente, on scanne et on ne récrée pas le fichier

            cur.execute("select count(*) from pool")
            if cur.fetchone()[0] > 0:
                for row in cur.execute(
                    "select timestamp from pool_scanned where filename=?", [self.pool]
                ):
                    can_load = self.get_pool_marker() <= row[0]
                    if can_load:
                        debug(1, "previous scan up to date")
                if not can_load:
                    debug(1, "previous scan out of date, will rescan")
            else:
                debug(1, "pool db is empty")

            if can_load:
                print("Loading pool {}".format(self.pool))

                for row in cur.execute("select filename,size from pool"):
                    self.pool_files[row[0]] = row[1]
            else:
                print("Scanning pool…")
                cur.execute("delete from pool_scanned")
                cur.execute("delete from pool")
                tmp = []
                r = [os.path.join(self.pool, "pool")]
                if os.path.isdir(r[0]):
                    while len(r) > 0:
                        for i in os.scandir(r.pop()):
                            if i.is_dir():
                                r.append(i.path)
                            elif i.is_file():
                                path = os.path.relpath(i.path, self.pool)
                                st = i.stat()

                                self.pool_files[path] = st.st_size

                                tmp.append((path, st.st_size))
                                if len(tmp) >= 100:
                                    cur.executemany(
                                        "insert into pool (filename,size) values (?,?)", tmp
                                    )
                                    tmp = []

                if len(tmp) > 0:
                    cur.executemany("insert into pool (filename,size) values (?,?)", tmp)

                cur.execute(
                    "insert into pool_scanned (filename,timestamp) values (?,?)",
                    (pool, self.set_pool_marker()),
                )

            cur.close()
            self.db.commit()

            print("Pool: {} file(s) listed".format(len(self.pool_files)))

    def find_missing(self):
        """
        cherche les fichiers manquants
        """

        assert self.pool

        print("Searching for missing files…")

        sql = "select filename,size,catalog_id from package where catalog_id in ({})".format(
            ",".join([str(i) for i in self.active_catalog])
        )
        cur = self.db.cursor()

        missing = set()
        catalog = set()

        for row in cur.execute(sql):

            filename = row[0]
            filesize = row[1]
            catalog_id = row[2]

            if self.pool_files is None:
                p = os.path.join(self.pool, filename)
                size = os.path.getsize(p) if os.path.exists(p) else -1
            else:
                size = self.pool_files.get(filename, -1)

            if size == -1:
                debug(3, "MISSING {} {} {}".format(self.pool, filename, filesize))
                missing.add(filename)
                catalog.add(catalog_id)
            else:
                if size != filesize:
                    debug(3, "BAD {} {} {}".format(self.pool, filename, filesize))
                    missing.add(filename)

        n = len(missing)
        if n > 0:
            print("Missing: {} file(s) from listed in:".format(n))
            sql = "select filename from catalog where catalog_id in ({}) order by filename".format(
                ",".join([str(i) for i in catalog])
            )
            for row in cur.execute(sql):
                print("  {}".format(row[0]))
        else:
            print("All files listed are present")

        cur.close()

        self.urls = sorted(missing)

        missing_file = os.path.join(self.tmp_dir, "missing")
        debug(1, "missing in " + missing_file)
        with open(missing_file, "w") as f:
            for i in sorted(self.urls):
                f.write(i)
                f.write("\n")

        return n

    def find_excess(self):
        """
        """
        self.excess = None
        try:
            os.unlink(os.path.join(self.tmp_dir, "excess"))
        except FileNotFoundError:
            pass

        n = 0

        if self.pool_files is not None:
            cur = self.db.cursor()

            total_size = 0
            with open(os.path.join(self.tmp_dir, "excess"), "w") as f:

                for row in cur.execute(
                    "select filename,size from pool where filename not in (select filename from package)"
                ):
                    n += 1
                    f.write(row[0])
                    f.write("\n")
                    total_size += row[1]

            cur.close()

            if n == 0:
                print("No file in excess")
            else:
                print("Excess: {} file(s) for {} byte(s)".format(n, total_size))
        else:
            print("Files in excess not searched")

        self.excess = n

    def wget(self, mirror, jobs=10):
        """
        crée le fichier de commandes wget
        """
        assert jobs >= 1 and jobs <= 20

        nb = len(self.urls)
        if nb == 0:
            debug(1, "no url to download...")

        # le fichier de commandes des wget
        cmd_file = os.path.join(self.tmp_dir, "wget_cmd.sh")
        f_cmd = open(cmd_file, "w")
        f_cmd.write("#! /bin/bash\n")
        f_cmd.write("#root {}\n".format(self.pool))

        f_cmd.write("\n")
        f_cmd.write("cd {}\n".format(os.path.abspath(os.path.curdir)))
        f_cmd.write("\n")

        # le nombre de répertoires dans l'url du mirror
        s = urllib.parse.urlsplit(mirror).path
        if s.endswith("/"):
            s = s[:-1]
        if s.endswith("/pool"):
            print("Mirror should not end with /pool ({})".format(mirror))
            return
        cut = str.count(s, "/")

        n = (nb + jobs - 1) // jobs
        k = 0
        j = 0
        f = None

        # create 'jobs' files of n lines each, except the last
        debug(2, "{} lines per file".format(n))
        for url in self.urls:
            if j == 0:
                if f is not None:
                    f.close()
                k += 1
                debug(1, "writing file {}, url count: {}".format(k, n - ((n * k) % nb) % n))

                log_file = "/dev/null"

                url_file = os.path.join(self.tmp_dir, "url.{}".format(k))
                log_file = os.path.join(self.tmp_dir, "log.{}".format(k))

                #   -nv             --no-verbose
                #   -x              --force-directories
                #   -nH             --no-host-directories
                #                   --cut-dirs=number
                #   -P prefix       --directory-prefix=prefix
                cmd = "wget -nv -x -nH -P {} --cut-dirs={} -i {} -o {}".format(
                    self.pool, cut, url_file, log_file
                )
                f_cmd.write(cmd + " &\n")

                f = open(url_file, "w")

            debug(3, posixpath.join(mirror, url))
            f.write(posixpath.join(mirror, url))
            f.write("\n")

            j += 1
            if j >= n:
                j = 0

        if f is not None:
            f.close()

        f_cmd.write("wait\n")
        f_cmd.close()
        os.chmod(cmd_file, stat.S_IRWXU)

        # debug(1, "cmd file: " + cmd_file)
        print("Writing download commands into {}".format(cmd_file))
        # with open(cmd_file) as f: print(f.read())

        # fichier de commande pour nettoyer
        cmd_file = os.path.join(self.tmp_dir, "clean.sh")
        f_cmd = open(cmd_file, "w")
        f_cmd.write("#! /bin/bash\n")
        f_cmd.write("\n")
        f_cmd.write("cd {}\n".format(os.path.abspath(os.path.curdir)))
        f_cmd.write("\n")
        f_cmd.write("cat {}/excess | (cd {} ; xargs rm -f)\n".format(self.tmp_dir, self.pool))
        f_cmd.write("\n")
        f_cmd.write("# find %s -type d -empty -exec rmdir {} \\;\n" % self.pool)
        f_cmd.close()
        os.chmod(cmd_file, stat.S_IRWXU)
        print("Writing cleaning commands into {}".format(cmd_file))


def main(args=None):
    """
    fonction principale
    """
    global verbosity

    parser = argparse.ArgumentParser(description="apt-mirror debian/ubuntu")
    parser.add_argument("-v", "--verbose", action="count", default=verbosity)
    parser.add_argument(
        "-d", "--dists", nargs="+", action="append", help="chemin de l'arborescence /dists/"
    )
    parser.add_argument("--dists-db", default=False, action="store_true")
    parser.add_argument(
        "-f", "--dists-file", nargs="+", action="append", help="fichier Packages ou Sources"
    )
    parser.add_argument("-p", "--pool", help="chemin de l'arborescence /pool/", default="debian")
    parser.add_argument(
        "-m", "--mirror", help="URL du serveur mirror", default="http://ftp.fr.debian.org/debian/"
    )
    parser.add_argument("-j", "--jobs", help="", type=int, default=1)
    parser.add_argument("-t", "--tmp-dir", help="")
    parser.add_argument(
        "-s",
        "--scan",
        help="cherche les fichiers en trop du pool",
        dest="scan_pool",
        action="store_true",
        default=False,
    )

    args = parser.parse_args(args=args)

    verbosity = args.verbose
    debug(2, "args=" + str(args))

    # début
    m = mirror(args.tmp_dir)

    # vérification du répertoire pool
    if not os.path.isdir(args.pool):
        debug(1, "not an existing dir: {}".format(args.pool))
        sys.exit(1)
    args.pool = os.path.normpath(args.pool)
    if os.path.basename(args.pool) == "pool":
        args.pool = os.path.dirname(args.pool)
    debug(1, "/pool/ " + args.pool)

    # analyse des répertoires récursivement, sans tenir des symlinks de plus haut niveau
    for paths in args.dists or {}:
        p = []
        for path in paths:
            p += glob.glob(path)
        paths = p
        for path in paths:
            debug(1, "/dists/ {}".format(path))

            if not os.path.isdir(path):
                debug(1, "not an existing dir: {}".format(path))
                continue

            path = os.path.normpath(path)
            if os.path.basename(path) != "dists" and os.path.isdir(os.path.join(path, "dists")):
                path = os.path.join(path, "dists")

            if m._unwanted(path):
                debug(1, "File ignored: {}".format(path))
                continue

            # debug(2, "scandir: " + path)
            print("Finding files from {}".format(path))
            for e in os.scandir(path):
                if e.is_dir(follow_symlinks=False):
                    debug(2, "analyzing dir: " + e.path)
                    for i in glob.iglob(os.path.join(e.path, "**"), recursive=True):
                        m.parse(i, path)

    # analyse des fichiers Packages et Sources nommés
    for filenames in args.dists_file or {}:
        for filename in filenames:
            debug(1, "dists_file {}".format(filename))
            if not os.path.isfile(filename):
                debug(1, "not an existing file: {}".format(path))
                continue
            m.parse(filename, os.path.dirname(filename))

    if args.dists_db:
        m.set_dists_db()

    # affichage du total
    m.total()

    # args.scan_pool = False
    m.set_pool(args.pool, args.scan_pool)
    m.find_missing()
    m.find_excess()
    m.wget(args.mirror, args.jobs)


if __name__ == "__main__":
    main()
