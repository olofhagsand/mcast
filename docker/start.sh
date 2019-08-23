#!/bin/sh
# Start script for mcast test container
# Copied to container by Dockerfile and triggered at start by CMD commnd

DIR=/mcast
WDIR=$DIR/www
FILE=$DIR/config
CGDIR=$WDIR/cgi-bin
PORT=80

>&2 echo "$0"

mkdir -p $WDIR
chown minihttpd $WDIR
mkdir -p $CGDIR
chown minihttpd $CGDIR

# config file
cat <<EOF > $FILE
dir=$WDIR
cgipat=cgi-bin/*
port=$PORT
EOF

# hello file
cat <<EOF > $WDIR/index.html
<h1>HELLO WORLD</h1>
EOF

# cgi-bin file
cat <<EOF > $CGDIR/reply.sh
#!/bin/sh
#
echo "Content-type: text/plain"
echo ""
echo "reply"
exit 0
EOF

chown minihttpd $CGDIR/reply.sh
chmod 755 $CGDIR/reply.sh 

>&2 echo "mini_httpd -C $FILE"
mini_httpd -D -C $FILE
