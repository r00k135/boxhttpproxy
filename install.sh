#!/usr/bin/env bash

if [ $(id -u) != 0 ]; then
   echo "The script need to be run as root, sudoing." >&2
   sudo $0 $@
   exit 1
fi

INSTALL_DIR="/usr"
BIN_DIR="$INSTALL_DIR/bin"
CONF_DIR="/etc/boxhttpproxy"
RUNNING_USER=boxproxy


echo "ID:"$(id -u)":Running install as root user..."

echo "Checking dependencies..."
source /etc/*-release
if [ "$DISTRIB_ID" = "Ubuntu" ]; then
	echo "Ubuntu install"
	INSTALLED=""
	CHK_PYTHON=`dpkg --get-selections | egrep "^python3"`
	if [ -z "$CHK_PYTHON" ]; then
		apt-get install -y python3
		INSTALLED="${INSTALLED}python3 "
	fi
	CHK_PYTHON=`dpkg --get-selections | egrep "^python3-pip"`
	if [ -z "$CHK_PYTHON" ]; then
		apt-get install -y python3-pip
		INSTALLED="${INSTALLED}python3-pip "
	fi
	CHK_PYTHON=`pip3 install --upgrade -r requirements.txt`
	CHK_PYTHON=`echo "${CHK_PYTHON}" | grep "Requirement already up-to-date"`
	if [ -z "$CHK_PYTHON" ]; then
		PYTHON_REQUIREMENTS=`cat requirements.txt | xargs`
		INSTALLED="${INSTALLED}${PYTHON_REQUIREMENTS} "
	fi
	if [ -n "$INSTALLED" ]; then
		echo -e "\nInstalled the following packages ${INSTALLED}"
	else
		echo "All packages are present"
	fi

fi

if [ ! -d "$CONF_DIR" ]; then
	echo "Creating config directory $CONF_DIR"
	mkdir -p "${CONF_DIR}/tokens"
fi
cp sample_boxhttpproxy.conf $CONF_DIR/boxhttpproxy.conf


RESULT=`useradd ${RUNNING_USER} 2>&1`
if [ -z "$RESULT" ]; then
	echo "Running user ${RUNNING_USER} already exists"
else
	echo "Created Running User ${RUNNING_USER}"
fi
chown -R "${RUNNING_USER}" "$CONF_DIR"

cp boxhttpserver.py ${INSTALL_DIR}/sbin
if [ ! -d "${INSTALL_DIR}/sbin" ]; then
	mkdir -p "${INSTALL_DIR}/sbin"
fi
chown "${RUNNING_USER}" "${INSTALL_DIR}/sbin/boxhttpserver.py"
chmod +x "${INSTALL_DIR}/sbin/boxhttpserver.py"

if [ "$DISTRIB_ID" = "Ubuntu" ]; then
	echo "Installing Ubuntu start scripts"
	cp boxhttpproxy /etc/init.d/
	chown root:root /etc/init.d/boxhttpproxy
	chmod +x /etc/init.d/boxhttpproxy
	update-rc.d boxhttpproxy defaults
	update-rc.d boxhttpproxy enable
	echo "Run with \"sudo /etc/init.d/boxhttpproxy start\""
fi

echo "Install complete"
