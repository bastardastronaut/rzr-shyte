
# rzr-router
contribute to the rzr-network by running this harmless piece of code on your publicly server.

## as simple as
```
npm install
export {OPTIONS}
node ./index.js
```

## Options
|name            |control                        |value                         |required|
|----------------|-------------------------------|------------------------------|:--------:|
|PRIVATE_KEY     |identification            |the private key (hexstring) you signed the registration signature with             |x|
|PORT            |Port used for the server    |number             |x|
|CONTRACT_ADDRESS|non-blockchain user identity generation support|0x38B3464AAd191A60b8b84cF24b6a77E4F00ED924 ||
|RPC_PROVIDER_ADDRESS|non-blockchain user identity generation support|your RPC provider address ||
|SUPPORTED_IDENTITY_REQUESTS_PER_HOUR|rate limiting for identity generation|number|
