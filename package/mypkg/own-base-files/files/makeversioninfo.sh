#! /bin/sh
prexdate=$(date +%y:%m|awk -F: '{printf("%01d.%02d\n",$1-15,$2)}')
gitcnt=$(git rev-list HEAD |wc -l|awk '{printf(".%s",$1)}')
version=$prexdate$gitcnt
[ -f ./files/firmwareinfo ] && rm -f ./files/firmwareinfo

cat > ./files/firmwareinfo <<EOF
config version 'info'
    option firmware_version '$version'

EOF

