aclocal -I m4
autoheader
autoconf
automake --foreign --add-missing --copy
autoreconf -I m4 --install --force 