LIST=0
if [ x$1 != x ]; then
    LIST=$1
fi

wapod-pherry deploy --worker-list $LIST --deposit 10000000000000
