#!/bin/bash

BASE="/home/sap"
PORT=7555
# Execute options
ARGS=$(getopt -o "hp:n:c:r:wsudx" -l "help,count:,net" -n "multinode_SAP.sh" -- "$@");

net=4
count=1
eval set -- "$ARGS";

while true; do
    case "$1" in
        -n|--net)
            shift;
                    if [ -n "$1" ];
                    then
                        net="$1";
                        shift;
                    fi
            ;;
        -c|--count)
            shift;
                    if [ -n "$1" ];
                    then
                        count="$1";
                        shift;
                    fi
            ;;
        --)
            shift;
            break;
            ;;
    esac
done
	
#######################-------------------------------------------------------------------------IP TESTING	

# break here of net isn't 4 or 6
if [ ${net} -ne 4 ] && [ ${net} -ne 6 ]; then
    echo "invalid NETWORK setting, can only be 4 or 6!"
    exit 1;
fi
	
if [ ${net} = 4 ]; then
	IPADDRESS=$(ip addr | grep 'inet ' | grep -Ev 'inet 127|inet 192\.168|inet 10\.' | sed "s/[[:space:]]*inet \([0-9.]*\)\/.*/\1/")
fi
	
if [ ${net} = 6 ]; then
	IPADDRESS=$(ip -6 addr show dev eth0 | grep inet6 | awk -F '[ \t]+|/' '{print $3}' | grep -v ^fe80 | grep -v ^::1 | cut -f1-4 -d':' | head -1)
fi
#######################-------------------------------------------------------------------------END IP TESTING

# currently only for Ubuntu 16.04 & 18.04
    if [[ -r /etc/os-release ]]; then
        . /etc/os-release
        if [[ "${VERSION_ID}" != "16.04" ]] && [[ "${VERSION_ID}" != "18.04" ]] ; then
            echo "This script only supports Ubuntu 16.04 & 18.04 LTS, exiting."
            exit 1
        fi
    else
        # no, thats not ok!
        echo "This script only supports Ubuntu 16.04 & 18.04 LTS, exiting."
        exit 1
    fi
	
#Check Deps
sudo apt-get install lshw
if [ -d "/var/lib/fail2ban/" ]; 
then
    echo -e "Dependencies already installed..."
else
    echo -e "Updating system and installing required packages..."

sudo DEBIAN_FRONTEND=noninteractive apt-get update -y
sudo apt-get -y upgrade
sudo apt-get -y dist-upgrade
sudo apt-get -y autoremove
sudo apt-get -y install wget nano htop jq
sudo apt-get -y install libzmq3-dev
sudo apt-get -y install libboost-system-dev libboost-filesystem-dev libboost-chrono-dev libboost-program-options-dev libboost-test-dev libboost-thread-dev lshw
sudo apt-get -y install libevent-dev
sudo apt-get instal unzip
sudo apt -y install software-properties-common
sudo add-apt-repository ppa:bitcoin/bitcoin -y
sudo apt-get -y update
sudo apt-get -y install libdb4.8-dev libdb4.8++-dev
sudo apt-get install unzip
sudo apt-get -y install libminiupnpc-dev
sudo apt-get -y install fail2ban
sudo service fail2ban restart
sudo apt-get install libdb5.3++-dev libdb++-dev libdb5.3-dev libdb-dev && ldconfig
sudo apt-get install -y unzip libzmq3-dev build-essential libssl-dev libboost-all-dev libqrencode-dev libminiupnpc-dev libboost-system1.58.0 libboost1.58-all-dev libdb4.8++ libdb4.8 libdb4.8-dev libdb4.8++-dev libevent-pthreads-2.0-5
fi 

#Create 2GB swap file
if grep -q "SwapTotal" /proc/meminfo; then
    echo -e "${GREEN}Skipping disk swap configuration...${NC} \n"
else
    echo -e "${YELLOW}Creating 2GB disk swap file. \nThis may take a few minutes!${NC} \a"
    touch /var/swap.img
    chmod 600 swap.img
    dd if=/dev/zero of=/var/swap.img bs=1024k count=2000
    mkswap /var/swap.img 2> /dev/null
    swapon /var/swap.img 2> /dev/null
    if [ $? -eq 0 ]; then
        echo '/var/swap.img none swap sw 0 0' >> /etc/fstab
        echo -e "${GREEN}Swap was created successfully!${NC} \n"
    else
        echo -e "${YELLOW}Operation not permitted! Optional swap was not created.${NC} \a"
        rm /var/swap.img
    fi
fi


echo '==========================================================================='
echo 'Finding querying for latest version' && wget https://raw.githubusercontent.com/methuselah-coin/version/master/stable
version=$(head -n 1 stable)
echo "$version"

methd=$(which methuselahd)

isInFile=$($methd -version | grep -c select <<< "$version")
if [ $isInFile -eq 1 ]; then
   update = 1
else
   update = 0
fi


# daemon not found compile it
        
#Stop Service----------------------------------
			
#NEED TO BUILD---------------------------------
#Download Latest
echo 'Downloading latest version:  wget https://github.com/methuselah-coin/methuselah/releases/download/v'"$version"'/methuselah-'"$version"'-linux.tar.xz' &&  wget https://github.com/methuselah-coin/methuselah/releases/download/v"$version"/methuselah-"$version"-linux.tar.xz
			
#Install Latest
echo '==========================================================================='
echo 'Extract new methuselah: \n# tar -xf methuselah-'"$version"'-linux.tar.xz -C /usr/local/bin' && tar -xf methuselah-$version-linux.tar.xz -C /usr/local/bin

rm methuselah-$version-linux.tar.xz
rm stable
# our new mnode unpriv user acc is added
if id "sap" >/dev/null 2>&1; then
    echo "user exists already, do nothing" 
else
    echo "Adding new system user sap"
    adduser --disabled-password --gecos "" sap
fi

netDisable=$(lshw -c network | grep -c 'network DISABLED')
venet0=$(cat /etc/network/interfaces | grep -c venet)

if [ $netDisable -ge 1 ]; then
	if [ $venet0 -ge 1 ]; 
	then
		dev2=venet0
	else
		echo 'Cannot use this script at this time'
		exit 1
	fi
else
	dev2=$(lshw -c network | grep logical | cut -d':' -f2 | cut -d' ' -f2)
fi

# individual data dirs for now to avoid problems
echo "* Creating masternode directories"
mkdir -p "$BASE"/multinode
for NUM in $(seq 1 ${count}); do
    if [ ! -d "$BASE"/multinode/SAP_"${NUM}" ]; then
        echo "creating data directory $BASE/multinode/SAP_${NUM}" 
        mkdir -p "$BASE"/multinode/SAP_"${NUM}" 
		#Generating Random Password for methuselahd JSON RPC
		USER=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
		USERPASS=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
		read -e -p "MasterNode Key for SAP_"${NUM}": " MKey
		echo "rpcallowip=127.0.0.1
rpcuser=$USER
rpcpassword=$USERPASS
server=1
daemon=1
listen=1
maxconnections=32
masternode=1
masternodeprivkey=$MKey
promode=1
addnode=node1.methuselahcoin.io:7555
addnode=node2.methuselahcoin.io:7555
addnode=node3.methuselahcoin.io:7555
addnode=node4.methuselahcoin.io:7555
addnode=node5.methuselahcoin.io:7555
addnode=node6.methuselahcoin.io:7555
addnode=node7.methuselahcoin.io:7555
addnode=node8.methuselahcoin.io:7555
addnode=node9.methuselahcoin.io:7555" |sudo tee -a "$BASE"/multinode/SAP_"${NUM}"/methuselah.conf >/dev/null

echo 'bind=192.168.1.'"${NUM}"':'"$PORT" >> "$BASE"/multinode/SAP_"${NUM}"/methuselah.conf
echo 'rpcport=500'"${NUM}" >> "$BASE"/multinode/SAP_"${NUM}"/methuselah.conf

echo 'ip addr del 192.168.1.'"${NUM}"'/32 dev '"$dev2"':'"${NUM}" >> start_multinode.sh
echo 'ip addr add 192.168.1.'"${NUM}"'/32 dev '"$dev2"':'"${NUM}" >> start_multinode.sh
echo "runuser -l sap -c 'methuselahd -daemon -pid=$BASE/multinode/SAP_${NUM}/methuselah.pid -conf=$BASE/multinode/SAP_${NUM}/methuselah.conf -datadir=$BASE/multinode/SAP_${NUM}'" >> start_multinode.sh

echo 'ip addr del 192.168.1.'"${NUM}"'/32 dev '"$dev2"':'"${NUM}" >> stop_multinode.sh
echo "methuselah-cli -conf=$BASE/multinode/SAP_${NUM}/methuselah.conf -datadir=$BASE/multinode/SAP_${NUM} stop" >> stop_multinode.sh

echo "echo '====================================================${NUM}========================================================================'" >> mn_status.sh
echo "methuselah-cli -conf=$BASE/multinode/SAP_${NUM}/methuselah.conf -datadir=$BASE/multinode/SAP_${NUM} masternode debug " >> mn_status.sh

echo "echo '====================================================${NUM}========================================================================'" >> getinfo.sh
echo "methuselah-cli -conf=$BASE/multinode/SAP_${NUM}/methuselah.conf -datadir=$BASE/multinode/SAP_${NUM} getinfo" >> mn_getinfo.sh

fi
done

chmod +x start_multinode.sh
chmod +x stop_multinode.sh
chmod +x mn_status.sh
chmod +x mn_getinfo.sh
cat start_multinode.sh >> /usr/local/bin/start_multinode.sh
cat stop_multinode.sh >> /usr/local/bin/stop_multinode.sh
cat mn_getinfo.sh >> /usr/local/bin/mn_getinfo.sh
cat mn_status.sh >> /usr/local/bin/mn_status.sh
chown -R sap:sap /home/sap/multinode
chmod -R g=u /home/sap/multinode

echo 'run start_multinode.sh to start the multinode'
echo 'run stop_multinode.sh to stop it'
echo 'run mn_getinfo.sh to see the status of all of the nodes'
echo 'run mn_status.sh for masternode debug of all the nodes'
echo "in masternode.conf file use the external IP address as the address ex. MN1 $IPADDRESS:7555 privekey tx_id tx_index"
