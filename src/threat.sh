if [[  (-z $1 || -z $2 || -z $3 || -z $4 || -z $5) ]]; then
	echo "USAGE: $0 <threads> <username> <server address> <server port> <password>"
	exit 1
fi

for ((i=0; i<$1; i++)); do
	java -cp .:./bcprov-jdk15on-162.jar ClientApplication << EOF &
$2
1
$3
$4
$5
8
3
EOF
done
wait
