
= build pre-reqs =

 Packages: automake, autoconf, libtool, gcc, openssl-devel

= build steps =

 $ autoreconf -ivf
 $ ./configure
 $ make
 # make install

= runtime pre-reqs =

 For using tpm-luks with a LUKS key on your rootfs volume: dracut grubby

 All uses: cryptsetup gawk coreutils tpm-tools-1.3.8 trousers-0.3.9

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
