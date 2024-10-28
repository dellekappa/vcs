step crypto rand 12 --format ascii | head -c${1:-12} > ./key.pwd
step crypto jwk create --kty EC --alg ES256 --crv P-256 jwk.pub.json jwk.priv.json --kid "" --password-file ./key.pwd