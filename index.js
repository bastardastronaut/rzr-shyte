"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const ethers_1 = require("ethers");
const ws_1 = require("ws");
const express_1 = __importDefault(require("express"));
const path_1 = __importDefault(require("path"));
const app = (0, express_1.default)();
const PORT = process.env.PORT || 8080;
const server = app.listen(PORT);
const privateKey = process.env.ROUTER_IDENTITY
const wss = new ws_1.WebSocketServer({
    server,
    path: "/signal",
    maxPayload: 2048,
    perMessageDeflate: {
        zlibDeflateOptions: {
            // See zlib defaults.
            chunkSize: 1024,
            memLevel: 7,
            level: 3,
        },
        zlibInflateOptions: {
            chunkSize: 10 * 1024,
        },
        // Other options settable:
        clientNoContextTakeover: true,
        serverNoContextTakeover: true,
        serverMaxWindowBits: 10,
        // Below options specified as default values.
        concurrencyLimit: 10,
        threshold: 1024, // Size (in bytes) below which messages
        // should not be compressed if context takeover is disabled.
    },
});
var SocketState;
(function (SocketState) {
    SocketState[SocketState["IDLE"] = 0] = "IDLE";
    SocketState[SocketState["AUTHENTICATING"] = 1] = "AUTHENTICATING";
    SocketState[SocketState["READY"] = 2] = "READY";
})(SocketState || (SocketState = {}));
var MessageType;
(function (MessageType) {
    MessageType[MessageType["PING"] = 0] = "PING";
    MessageType[MessageType["CLIENT_UNAVAILABLE"] = 1] = "CLIENT_UNAVAILABLE";
    MessageType[MessageType["OFFER"] = 2] = "OFFER";
    MessageType[MessageType["ANSWER"] = 3] = "ANSWER";
    MessageType[MessageType["CANDIDATE"] = 4] = "CANDIDATE";
})(MessageType || (MessageType = {}));
const clients = new Map();
const identity = new ethers_1.Wallet(privateKey);
function processIdentify(client, data) {
    if (data.byteLength !== 52)
        return;
    client.identity = ethers_1.utils.hexlify(data.slice(0, 20));
    client.state = SocketState.AUTHENTICATING;
    client.authMessage = ethers_1.utils.randomBytes(24);
    identity.signMessage(data.slice(20)).then(signature => {
        client.ws.send(ethers_1.utils.concat([client.authMessage, signature]));
    });
}
function processAuthentication(client, data) {
    if (ethers_1.utils.verifyMessage(client.authMessage, data).toLowerCase() !==
        client.identity) {
        client.ws.send(new Uint8Array([0]));
        return;
    }
    clients.set(ethers_1.utils.hexlify(client.identity), client);
    client.state = SocketState.READY;
    client.ws.send(new Uint8Array([1]));
}
function relay(messageType, from, data) {
    const client = clients.get(ethers_1.utils.hexlify(data.slice(0, 20)));
    if (!(client === null || client === void 0 ? void 0 : client.identity) || client.state !== SocketState.READY) {
        from.ws.send(ethers_1.utils.concat([
            new Uint8Array([MessageType.CLIENT_UNAVAILABLE]),
            data.slice(0, 20),
        ]));
        return;
    }
    client.ws.send(ethers_1.utils.concat([
        new Uint8Array([messageType]),
        from.identity,
        data.slice(20),
    ]));
}
function processMessage(client, data) {
    switch (data[0]) {
        case MessageType.PING:
        case MessageType.OFFER:
        case MessageType.ANSWER:
        case MessageType.CANDIDATE:
            return relay(data[0], client, data.slice(1));
        default:
    }
}
wss.on("connection", function connection(ws) {
    const client = {
        state: SocketState.IDLE,
        identity: null,
        authMessage: new Uint8Array(),
        ws,
    };
    ws.on("open", function () { });
    ws.on("close", function () {
        client.state = SocketState.IDLE;
        if (client.identity)
            clients.delete(ethers_1.utils.hexlify(client.identity));
    });
    ws.on("message", function message(data) {
        (() => {
            switch (client.state) {
                case SocketState.IDLE:
                    return processIdentify(client, data);
                case SocketState.AUTHENTICATING:
                    return processAuthentication(client, data);
                case SocketState.READY:
                    return processMessage(client, data);
                default:
                    return client;
            }
        })();
    });
});
app.use(express_1.default.static(__dirname + "/public"));
app.get("/", (req, res) => {
    res.sendFile(path_1.default.join(__dirname + "/public/index.html"));
});
console.log(`up & running on port ${PORT}`);
