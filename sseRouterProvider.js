"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const ethers_1 = require("ethers");
const clients = new Map();
exports.default = (app, wallet) => {
    function authenticate(timestamp, signature) {
        return (0, ethers_1.verifyMessage)((0, ethers_1.getBytes)((0, ethers_1.concat)([
            new TextEncoder().encode("RzR"),
            (0, ethers_1.zeroPadValue)((0, ethers_1.toBeArray)(timestamp), 6),
            wallet.address,
        ])), signature).toLowerCase();
    }
    function parseBody(input) {
        if (input.length < 91 || input.length > 2048)
            return 400;
        const timestamp = input.slice(0, 6);
        const signature = input.slice(6, 71);
        const sender = authenticate((0, ethers_1.toNumber)(timestamp), (0, ethers_1.hexlify)(signature));
        if (!clients.get(sender))
            return 401;
        return (0, ethers_1.getBytes)((0, ethers_1.concat)([sender, input.slice(91)]));
    }
    function getTarget(input) {
        return (0, ethers_1.hexlify)(input.slice(71, 91));
    }
    function send(response, messageType, message) {
        response.write(`event: ${messageType}\ndata: ${(0, ethers_1.encodeBase64)(message)}\n\n`);
    }
    function relayRequest(req, res, messageType) {
        const message = parseBody(req.body);
        if (typeof message === "number")
            return res.sendStatus(message);
        const client = clients.get(getTarget(req.body));
        if (!client)
            return res.sendStatus(404);
        send(client, messageType, message);
        res.sendStatus(200);
    }
    app.post("/ping", (req, res) => relayRequest(req, res, "ping"));
    app.post("/offer", (req, res) => relayRequest(req, res, "offer"));
    app.post("/answer", (req, res) => relayRequest(req, res, "answer"));
    app.post("/candidate", (req, res) => relayRequest(req, res, "candidate"));
    app.post("/unavailable", (req, res) => relayRequest(req, res, "unavailable"));
    app.get("/signals", (req, res) => {
        var _a, _b;
        // obviously need to verify these two...
        const timestamp = parseInt((_a = req === null || req === void 0 ? void 0 : req.query) === null || _a === void 0 ? void 0 : _a.timestamp);
        const signature = (0, ethers_1.decodeBase64)((_b = req === null || req === void 0 ? void 0 : req.query) === null || _b === void 0 ? void 0 : _b.signature);
        const now = new Date().getTime() / 1000;
        if (isNaN(timestamp) || timestamp < now - 15)
            return res.end();
        // TODO: need signature verification and make sure user is registered on chain
        const address = authenticate(timestamp, (0, ethers_1.hexlify)(signature));
        clients.set(address, res);
        res.writeHead(200, {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            Connection: "keep-alive",
        });
        // Listen for the client closing the connection
        req.on("close", () => {
            clients.delete(address);
            res.end();
        });
    });
};
