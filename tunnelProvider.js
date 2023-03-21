"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const ethers_1 = require("ethers");
const ws_1 = require("ws");
exports.default = (server, wallet) => {
    const wss = new ws_1.WebSocketServer({
        server,
        path: "/tunnel",
        maxPayload: 65536,
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
    const clients = new Map();
    function processAuthentication(client, data) {
        const timestamp = data.slice(0, 6);
        const signature = data.slice(6);
        // also check if player exists...
        client.identity = (0, ethers_1.verifyMessage)((0, ethers_1.getBytes)((0, ethers_1.concat)([new TextEncoder().encode("RzR"), timestamp, wallet.address])), (0, ethers_1.hexlify)(signature)).toLowerCase();
        if ((0, ethers_1.toNumber)(timestamp) < Math.floor(new Date().getTime() / 1000) - 60) {
            client.ws.send(new Uint8Array([0]));
            return;
        }
        clients.set(client.identity, client);
        client.state = SocketState.READY;
        client.ws.send(new Uint8Array([1]));
    }
    function forward(from, data) {
        const client = clients.get((0, ethers_1.hexlify)(data.slice(0, 20)));
        if (!(client === null || client === void 0 ? void 0 : client.identity) || client.state !== SocketState.READY) {
            from.ws.send((0, ethers_1.getBytes)((0, ethers_1.concat)([new Uint8Array([0]), data.slice(0, 20)])));
            return;
        }
        client.ws.send(data.slice(20));
    }
    wss.on("connection", function connection(ws) {
        const client = {
            state: SocketState.AUTHENTICATING,
            identity: null,
            ws,
        };
        ws.on("open", function () {
            client.state = SocketState.AUTHENTICATING;
        });
        ws.on("close", function () {
            client.state = SocketState.IDLE;
            if (client.identity) {
                clients.delete((0, ethers_1.hexlify)(client.identity));
                for (const c of clients.values()) {
                    c.ws.send((0, ethers_1.getBytes)((0, ethers_1.concat)([new Uint8Array([0]), client.identity])));
                }
            }
        });
        ws.on("message", function message(data) {
            (() => {
                switch (client.state) {
                    case SocketState.AUTHENTICATING:
                        return processAuthentication(client, data);
                    case SocketState.READY:
                        return forward(client, data);
                    default:
                        return client;
                }
            })();
        });
    });
};
