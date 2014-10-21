#! /bin/sh
set -x
aclocal -I autotools
case `uname` in 
	Darwin*) glibtoolize --copy --force ;;
  	*) libtoolize --force --copy ;; 
esac
autoheader
automake --add-missing --copy
autoconf

