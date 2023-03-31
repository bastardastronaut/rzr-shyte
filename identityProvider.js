"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const ethers_1 = require("ethers");
let requests = [];
const BLOCK_BYTE_LENGTH = 105; // 32 + 32 + 20 + 20 + 1
// at 10K active monthly users -> 1M not bad!
const ABI = [
    {
        anonymous: false,
        inputs: [
            {
                indexed: true,
                internalType: "address",
                name: "addr1",
                type: "address",
            },
            {
                indexed: true,
                internalType: "address",
                name: "addr2",
                type: "address",
            },
            {
                indexed: false,
                internalType: "enum RzRIdentities.EventType",
                name: "eventType",
                type: "uint8",
            },
            {
                indexed: false,
                internalType: "bytes32",
                name: "data",
                type: "bytes32",
            },
        ],
        name: "Event",
        type: "event",
    },
    {
        inputs: [],
        name: "latestHash",
        outputs: [
            {
                internalType: "bytes32",
                name: "",
                type: "bytes32",
            },
        ],
        stateMutability: "view",
        type: "function",
    },
    {
        inputs: [
            {
                internalType: "address",
                name: "account",
                type: "address",
            },
            {
                internalType: "address",
                name: "identity",
                type: "address",
            },
            {
                internalType: "uint8",
                name: "_v",
                type: "uint8",
            },
            {
                internalType: "bytes32",
                name: "_r",
                type: "bytes32",
            },
            {
                internalType: "bytes32",
                name: "_s",
                type: "bytes32",
            },
        ],
        name: "registerIdentity",
        outputs: [],
        stateMutability: "nonpayable",
        type: "function",
    },
];
exports.default = (app, wallet, clients, contractAddress, hourlyRequestLimit) => {
    const contract = new ethers_1.Contract(contractAddress, ABI, wallet);
    const isEligibleForRequest = (commit = false) => {
        const now = Math.round(new Date().getTime() / 1000);
        let hourlyRequestCount = 0;
        let cutoff = 0;
        for (let i = 0; i < requests.length; ++i) {
            if (requests[i] < now - 3600 && cutoff === 0) {
                cutoff = i;
            }
            else {
                hourlyRequestCount++;
            }
        }
        requests = requests.slice(cutoff);
        if (hourlyRequestCount > hourlyRequestLimit) {
            return false;
        }
        if (commit)
            requests.push(now);
        return true;
    };
    const provider = wallet.provider;
    console.log("downloading blockchain data...");
    // TODO: eventually add support for other blockchains?
    Promise.all([
        provider.getBlockNumber(),
        contract.latestHash(),
        contract.queryFilter("Event"), // TODO: this will take a block number
    ]).then(([blockNumber, latestHash, events]) => {
        // TODO: now the below is admittedly not the most efficient, but gets the job done in a few lines of code.
        const eventToBytes = (e) => (0, ethers_1.concat)([
            (0, ethers_1.zeroPadValue)((0, ethers_1.toBeArray)(e.blockNumber), 32),
            (0, ethers_1.dataSlice)(e.data, 31, 32),
            (0, ethers_1.dataSlice)(e.topics[1], 12),
            (0, ethers_1.dataSlice)(e.topics[2], 12),
            (0, ethers_1.dataSlice)(e.data, 32),
        ]);
        const eventLog = events
            .filter((e) => !e.removed)
            .map((e) => eventToBytes(e));
        let hash = (0, ethers_1.hexlify)(new Uint8Array(32)); // TODO: this will be seeded
        for (const event of eventLog) {
            hash = (0, ethers_1.sha256)((0, ethers_1.concat)([hash, event]));
        }
        console.log(`verifying hash ${hash} vs ${latestHash}`);
        if (hash !== latestHash)
            throw new Error("on-chain data incosistency, check your initial parameters");
        console.log("ethereum endpoints available");
        // TODO: Good enough for POC but not production ready. we are assuming here that providers are sending events in the order of being mined, this won't be the case however, not only can a higher blockNumber event arrive before a lower one, event in the same block the order of events won't necessarily match. probably best to do a timeout and re-request all events between already mined blocks to ensure data security.
        contract.on("Event", (_, __, ___, ____, { log }) => {
            const eventBytes = eventToBytes(log);
            hash = (0, ethers_1.sha256)((0, ethers_1.concat)([hash, eventBytes]));
            blockNumber = log.blockNumber;
            eventLog.push(eventBytes);
            // broadcast new event to all clients
            for (const client of clients) {
                client.response.write(`event: hash\ndata: ${hash}\n\n`);
            }
        });
        app.get("/latest-block", (req, res) => {
            res.send((0, ethers_1.encodeBase64)((0, ethers_1.concat)([(0, ethers_1.zeroPadValue)((0, ethers_1.toBeArray)(blockNumber), 6), hash])));
        });
        app.get("/event-log", (req, res) => {
            var _a, _b;
            const blockHeight = ((_a = req.query) === null || _a === void 0 ? void 0 : _a.blockHeight) || 0;
            const blockTarget = ((_b = req.query) === null || _b === void 0 ? void 0 : _b.blockTarget) || blockNumber;
            // TODO: this should be binary searched...
            const start = eventLog.findIndex((e) => (0, ethers_1.toNumber)((0, ethers_1.dataSlice)(e, 0, 32)) > blockHeight);
            if (start === -1)
                return res.sendStatus(404);
            const end = eventLog.findIndex((e) => (0, ethers_1.toNumber)((0, ethers_1.dataSlice)(e, 0, 32)) > blockTarget);
            // it accepts a blocknumber after which we return everything
            res.send((0, ethers_1.encodeBase64)((0, ethers_1.concat)(eventLog.slice(start, end === -1 ? undefined : end))));
        });
        app.get("/identity", (req, res) => {
            // to let client know, that identity generation is supported
            res.sendStatus(isEligibleForRequest() ? 200 : 429);
        });
        // add rate limiting to the below...
        app.post("/identity", (req, res) => {
            if (req.body.byteLength !== 105)
                return res.send(400);
            const account = (0, ethers_1.hexlify)(new Uint8Array(req.body.slice(0, 20)));
            const identity = (0, ethers_1.hexlify)(new Uint8Array(req.body.slice(20, 40)));
            const signature = (0, ethers_1.hexlify)(new Uint8Array(req.body.slice(40)));
            if ((0, ethers_1.verifyMessage)((0, ethers_1.getBytes)((0, ethers_1.concat)([account, identity])), signature).toLowerCase() !== (0, ethers_1.hexlify)(account) ||
                !isEligibleForRequest(true))
                return res.send(400);
            const { v, r, s } = ethers_1.Signature.from(signature);
            contract
                .registerIdentity(account, identity, v, r, s)
                .then((transaction) => {
                return new Promise((r) => {
                    const checkBlockNumber = (n = 0) => __awaiter(void 0, void 0, void 0, function* () {
                        var _a;
                        if ((_a = (yield provider.getTransactionReceipt(transaction.hash))) === null || _a === void 0 ? void 0 : _a.blockNumber)
                            r(true);
                        else if (n > 45)
                            r(false);
                        else
                            setTimeout(() => checkBlockNumber(n + 1), 3000);
                    });
                    checkBlockNumber();
                });
            })
                .then((success) => {
                res.sendStatus(success ? 200 : 500);
            })
                .catch((e) => {
                console.log(e);
                res.sendStatus(500);
            });
        });
    });
};
