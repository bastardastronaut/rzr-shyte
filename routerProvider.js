"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const ethers_1 = require("ethers");
const ws_1 = require("ws");
exports.default = (server, wallet) => {
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
    let SocketState;
    (function (SocketState) {
        SocketState[SocketState["IDLE"] = 0] = "IDLE";
        SocketState[SocketState["AUTHENTICATING"] = 1] = "AUTHENTICATING";
        SocketState[SocketState["READY"] = 2] = "READY";
    })(SocketState || (SocketState = {}));
    let MessageType;
    (function (MessageType) {
        MessageType[MessageType["PING"] = 0] = "PING";
        MessageType[MessageType["CLIENT_UNAVAILABLE"] = 1] = "CLIENT_UNAVAILABLE";
        MessageType[MessageType["OFFER"] = 2] = "OFFER";
        MessageType[MessageType["ANSWER"] = 3] = "ANSWER";
        MessageType[MessageType["CANDIDATE"] = 4] = "CANDIDATE";
    })(MessageType || (MessageType = {}));
    const clients = new Map();
    function processIdentify(client, data) {
        if (data.byteLength !== 52)
            return;
        client.identity = (0, ethers_1.hexlify)(data.slice(0, 20));
        client.state = SocketState.AUTHENTICATING;
        wallet.signMessage(data.slice(20)).then((signature) => {
            client.ws.send((0, ethers_1.getBytes)(signature));
        });
    }
    function processAuthentication(client, data) {
        const timestamp = data.slice(0, 6);
        const signature = data.slice(6);
        if ((0, ethers_1.toNumber)(timestamp) < Math.floor(new Date().getTime() / 1000) - 60 ||
            (0, ethers_1.verifyMessage)((0, ethers_1.getBytes)((0, ethers_1.concat)([timestamp, wallet.address])), (0, ethers_1.hexlify)(signature)).toLowerCase() !== client.identity) {
            client.ws.send(new Uint8Array([0]));
            return;
        }
        clients.set((0, ethers_1.hexlify)(client.identity), client);
        client.state = SocketState.READY;
        client.ws.send(new Uint8Array([1]));
    }
    function forward(messageType, from, data) {
        const client = clients.get((0, ethers_1.hexlify)(data.slice(0, 20)));
        if (!(client === null || client === void 0 ? void 0 : client.identity) || client.state !== SocketState.READY) {
            from.ws.send((0, ethers_1.getBytes)((0, ethers_1.concat)([
                new Uint8Array([MessageType.CLIENT_UNAVAILABLE]),
                data.slice(0, 20),
            ])));
            return;
        }
        client.ws.send((0, ethers_1.getBytes)((0, ethers_1.concat)([
            new Uint8Array([messageType]),
            from.identity,
            data.slice(20),
        ])));
    }
    function processMessage(client, data) {
        switch (data[0]) {
            case MessageType.PING:
            case MessageType.OFFER:
            case MessageType.ANSWER:
            case MessageType.CANDIDATE:
            case MessageType.CLIENT_UNAVAILABLE:
                return forward(data[0], client, data.slice(1));
            default:
        }
    }
    wss.on("connection", function connection(ws) {
        const client = {
            state: SocketState.IDLE,
            identity: null,
            ws,
        };
        ws.on("open", function () { });
        ws.on("close", function () {
            client.state = SocketState.IDLE;
            if (client.identity)
                clients.delete((0, ethers_1.hexlify)(client.identity));
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
};
