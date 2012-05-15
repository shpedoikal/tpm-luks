
= build pre-reqs =

 Packages: automake, autoconf, libtool, gcc, openssl-devel

= build steps =

 $ autoreconf -ivf
 $ ./configure
 $ make
 # make install

= runtime pre-reqs =

 Packages: cryptsetup dracut gawk coreutils grubby tpm-tools trousers

 tpm-luks requires very recent tpm-tools and trousers versions, likely not
included in your distro. To get these versions, you'll need to install them
from their upstream repositories:

 $ git clone git://trousers.git.sourceforge.net/gitroot/trousers/trousers trousers.git
 $ git clone git://trousers.git.sourceforge.net/gitroot/trousers/tpm-tools tpm-tools.git
 $ cd trousers.git
 $ sh bootstrap.sh
 $ ./configure
 $ make
 # make install
 $ cd ../tpm-tools.git
 $ sh bootstrap.sh
 $ ./configure
 $ make
 # make install

EOF
