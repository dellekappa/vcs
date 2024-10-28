if [ $# -eq 0 ]
  then
    echo "No arguments supplied"
    exit 1
fi

basepath=$(dirname -- $(readlink -fn -- "$0"))
nonce=${1}

echo -n "{\"iss\": \"wallet-poste\", \"aud\": \"https://guiding-tightly-shepherd.ngrok-free.app/oidc/idp/acme_issuer/v1.0\", \"iat\": $(date +%s), \"nonce\": \"${nonce}\"}" | step crypto jws sign --key ${basepath}/jwk.priv.json --password-file ${basepath}/key.pwd --typ openid4vci-proof+jwt --kid "did:jwk:$(basenc --base64url -w 0 < ${basepath}/jwk.pub.json)#0"