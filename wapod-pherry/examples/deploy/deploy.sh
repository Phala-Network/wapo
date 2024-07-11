L=0
if [ x$1 != x ]; then
L=$1
fi
cargo run -- deploy --worker-list $L --deposit 10000000000000
