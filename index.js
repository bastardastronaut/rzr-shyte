"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const ethers_1 = require("ethers");
const fs_1 = require("fs");
const cors_1 = __importDefault(require("cors"));
const express_1 = __importDefault(require("express"));
const body_parser_1 = __importDefault(require("body-parser"));
const tunnelProvider_1 = __importDefault(require("./tunnelProvider"));
const sseRouterProvider_1 = __importDefault(require("./sseRouterProvider"));
const identityProvider_1 = __importDefault(require("./identityProvider"));
const applicationProvider_1 = __importDefault(require("./applicationProvider"));
const PORT = process.env.PORT;
const IDENTITY = process.env.IDENTITY;
// TODO: eventually add starting point
// blockNumber + latestHash
// only fill these in if you want to support identity generation
const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS;
const RPC_PROVIDER_ADDRESS = process.env.RPC_PROVIDER_ADDRESS;
const SUPPORTED_IDENTITY_REQUESTS_PER_HOUR = parseInt(process.env.SUPPORTED_IDENTITY_REQUESTS_PER_HOUR || "0");
const PATH = `${__dirname}/${process.env.APP_PATH || "/public"}`;
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
(0, tunnelProvider_1.default)(server, nodeWallet);
app.use((0, cors_1.default)());
app.use(body_parser_1.default.raw());
const clients = (0, sseRouterProvider_1.default)(app, nodeWallet);
if (RPC_PROVIDER_ADDRESS) {
    (0, identityProvider_1.default)(app, nodeWallet, clients, CONTRACT_ADDRESS, SUPPORTED_IDENTITY_REQUESTS_PER_HOUR);
}
// also send back
// -> supported protocols
// maybe a router should support both by default
// actually we can do so, so that routing is going to be hybrid,
// long lived permanent connections are through websocket
// short lived are through sse
// wiring happens here
app.get("/self", (req, res) => {
    res.send(nodeWallet.address);
});
if ((0, fs_1.existsSync)(PATH)) {
    (0, applicationProvider_1.default)(app, PATH);
}
console.log(`up & running on port ${PORT}`);
