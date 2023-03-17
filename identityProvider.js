"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const ethers_1 = require("ethers");
const body_parser_1 = __importDefault(require("body-parser"));
const cors_1 = __importDefault(require("cors"));
let requests = [];
const ABI = [
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
exports.default = (app, wallet, contractAddress, hourlyRequestLimit) => {
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
    app.use(body_parser_1.default.raw());
    app.use((0, cors_1.default)());
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
        const contract = new ethers_1.Contract(contractAddress, ABI, wallet);
        contract
            .registerIdentity(account, identity, v, r, s)
            .then(() => {
            res.sendStatus(200);
        })
            .catch((e) => {
            console.log(e);
            res.sendStatus(500);
        });
    });
};
