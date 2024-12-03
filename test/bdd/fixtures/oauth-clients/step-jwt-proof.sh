#Copyright SecureKey Technologies Inc. All Rights Reserved.
#
#SPDX-License-Identifier: Apache-2.0

if [ $# -lt 2 ]
  then
    echo "You must provide audience and nonce args"
    exit 1
fi

basepath=$(dirname -- $(readlink -fn -- "$0"))
aud=${1}
nonce=${2}

echo -n "{\"iss\": \"wallet-poste\", \"aud\": \"${aud}\", \"iat\": $(date +%s), \"nonce\": \"${nonce}\"}" | step crypto jws sign --key ${basepath}/jwk.priv.json --password-file ${basepath}/key.pwd --typ openid4vci-proof+jwt --kid "did:jwk:$(basenc --base64url -w 0 < ${basepath}/jwk.pub.json)#0"