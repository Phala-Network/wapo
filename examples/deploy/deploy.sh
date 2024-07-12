L=0
if [ x$1 != x ]; then
L=$1
fi

wapod-pherry deploy --worker-list $L --deposit 10000000000000
