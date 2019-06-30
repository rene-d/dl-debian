#! /usr/bin/env bash
# rene-d 2019

mirror=$HOME/data
verbose=-v

#
# debian mirror
#
#   distributions:  stretch buster
#   architectures:  i386 amd64
#   sections:       main contrib non-free +debian-installer
#
debmirror \
	${mirror}/debian \
	--host=ftp.fr.debian.org \
	--dist=stretch,stretch-backports,stretch-proposed-updates,stretch-updates,buster,buster-backports,buster-proposed-updates,buster-updates \
	--arch=amd64,i386,all \
    --section=main,contrib,non-free,main/debian-installer,contrib/debian-installer,non-free/debian-installer \
	--root=/debian \
	--method=rsync \
	--i18n \
	--disable-ssl-verification \
	--no-check-gpg \
	--ignore-small-errors \
	--diff=none \
	--gzip-options=-9 \
	--di-dist=stretch,buster \
    --di-arch=amd64,i386,all \
    ${verbose}


#
# debian-security mirror
#
#   distributions:  stretch buster
#   architectures:  i386 amd64
#   sections:       main +debian-installer
#
debmirror \
	${mirror}/debian-security \
	--host=security.debian.org \
	--dist=stretch/updates,buster/updates \
    --section=main,main/debian-installer \
	--arch=amd64,i386 \
	--root=/debian-security \
	--method=rsync \
	--i18n \
	--no-check-gpg \
	--ignore-small-errors \
	--diff=none \
	--gzip-options=-9 \
    ${verbose}


[[ "$1" == "--check" ]] || exit

#
# rsync debian/dists/
#
root=${mirror}/dists-mirror
if [ $verbose ]; then rsync_opt='--verbose'; else rsync_opt='--quiet'; fi
mkdir -p ${root}

rsync ${rsync_opt} --delete -lptgoD rsync://ftp.fr.debian.org/debian/dists     ${root}/debian
rsync ${rsync_opt} --delete -a rsync://ftp.fr.debian.org/debian/zzz-dists      ${root}/debian
rsync ${rsync_opt} --delete -a rsync://ftp.fr.debian.org/debian/dists/stretch* ${root}/debian/dists
rsync ${rsync_opt} --delete -a rsync://ftp.fr.debian.org/debian/dists/buster*  ${root}/debian/dists

rsync ${rsync_opt} --delete -a rsync://security.debian.org/debian-security/zzz-dists     ${root}/debian-security
rsync ${rsync_opt} --delete -a rsync://security.debian.org/debian-security/dists/stretch ${root}/debian-security/dists
rsync ${rsync_opt} --delete -a rsync://security.debian.org/debian-security/dists/buster  ${root}/debian-security/dists


#
# check for missing files
#
./check.py -vv --scan --tmp-dir .tmp \
        --pool=${mirror}/debian \
        --dists="${mirror}/dists-mirror/debian/dists"
