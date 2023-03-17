"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const ethers_1 = require("ethers");
const fs_1 = require("fs");
const express_1 = __importDefault(require("express"));
const routerProvider_1 = __importDefault(require("./routerProvider"));
const identityProvider_1 = __importDefault(require("./identityProvider"));
const applicationProvider_1 = __importDefault(require("./applicationProvider"));
const PORT = process.env.PORT;
const IDENTITY = process.env.IDENTITY;
// only fill these in if you want to support identity generation
const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS;
const RPC_PROVIDER_ADDRESS = process.env.RPC_PROVIDER_ADDRESS;
const SUPPORTED_IDENTITY_REQUESTS_PER_HOUR = parseInt(process.env.SUPPORTED_IDENTITY_REQUESTS_PER_HOUR || '0');
const PATH = `${__dirname}/public`;
const app = (0, express_1.default)();
const server = app.listen(PORT);
// also needs to be able to serve the app
// /rzr.tar -> the source
// /app -> the compiled source, where the hash of index.html + js = on source hash
// so basically each game MUST have its own UI, they don't need their own interface though
// requires deterministic build
const provider = RPC_PROVIDER_ADDRESS
    ? new ethers_1.JsonRpcProvider(RPC_PROVIDER_ADDRESS)
    : null;
const nodeWallet = new ethers_1.Wallet(IDENTITY, provider);
(0, routerProvider_1.default)(server, nodeWallet);
if (RPC_PROVIDER_ADDRESS) {
    (0, identityProvider_1.default)(app, nodeWallet, CONTRACT_ADDRESS, SUPPORTED_IDENTITY_REQUESTS_PER_HOUR);
}
if ((0, fs_1.existsSync)(PATH)) {
    (0, applicationProvider_1.default)(app, PATH);
}
console.log(`up & running on port ${PORT}`);
