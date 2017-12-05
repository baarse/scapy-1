PIP=`which pip || (python --version | grep -q 'Python 2' && which pip2) || (python --version | grep -q 'Python 3' && which pip3)`

# Install dependencies using pip
if [ -z "$SCAPY_SUDO" -o "$SCAPY_SUDO" = "false" ]
then
  SCAPY_SUDO=""
  if [ "$TRAVIS_OS_NAME" = "osx" ]
  then
    PIP_INSTALL_FLAGS="--user"
  fi
else
  SCAPY_SUDO="$SCAPY_SUDO -H"
fi

$SCAPY_SUDO `which pip` install $PIP_INSTALL_FLAGS -U mock

if ! python --version 2>&1 | grep -q PyPy; then
  # cryptography requires PyPy >= 2.6, Travis CI uses 2.5.0
  $SCAPY_SUDO `which pip` install $PIP_INSTALL_FLAGS -U cryptography
fi

# Install coverage
if [ "$SCAPY_COVERAGE" = "yes" ]
then
  $SCAPY_SUDO `which pip` install $PIP_INSTALL_FLAGS -U coverage
  $SCAPY_SUDO `which pip` install $PIP_INSTALL_FLAGS -U PyX
  $SCAPY_SUDO `which pip` install $PIP_INSTALL_FLAGS -U codecov
fi

# Install pcap & dnet
if [ ! -z $SCAPY_USE_PCAPDNET ]
then
  if [ "$TRAVIS_OS_NAME" = "linux" ]
  then
    $SCAPY_SUDO apt-get install openssl
    $SCAPY_SUDO `which pip` install $PIP_INSTALL_FLAGS -U pylibpcap
    $SCAPY_SUDO `which pip` install $PIP_INSTALL_FLAGS -U pydumbnet
  elif [ "$TRAVIS_OS_NAME" = "osx" ]
  then
    mkdir -p /Users/travis/Library/Python/2.7/lib/python/site-packages
    echo 'import site; site.addsitedir("/usr/local/lib/python2.7/site-packages")' >> /Users/travis/Library/Python/2.7/lib/python/site-packages/homebrew.pth
 
    brew update
    brew install --with-python libdnet
    brew install .travis/pylibpcap.rb
  fi
fi

# Install wireshark data
if [ ! -z "$SCAPY_SUDO" ] && [ "$TRAVIS_OS_NAME" = "linux" ]
then
  $SCAPY_SUDO apt-get install libwireshark-data
fi
