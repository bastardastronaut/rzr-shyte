"use strict";
var __importDefault =
  (this && this.__importDefault) ||
  function (mod) {
    return mod && mod.__esModule ? mod : { default: mod };
  };
Object.defineProperty(exports, "__esModule", { value: true });
const ethers_1 = require("ethers");
const ws_1 = require("ws");
const express_1 = __importDefault(require("express"));
const path_1 = __importDefault(require("path"));
const cors_1 = __importDefault(require("cors"));
const body_parser_1 = __importDefault(require("body-parser"));
const PORT = process.env.PORT;
const IDENTITY = process.env.IDENTITY;
const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS;
const RPC_PROVIDER_ADDRESS = process.env.RPC_PROVIDER_ADDRESS;
const app = (0, express_1.default)();
const server = app.listen(PORT);
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
// also needs to be able to serve the app
// /rzr.tar -> the source
// /app -> the compiled source, where the hash of index.html + js = on source hash
// so basically each game MUST have its own UI, they don't need their own interface though
// requires deterministic build
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
  SocketState[(SocketState["IDLE"] = 0)] = "IDLE";
  SocketState[(SocketState["AUTHENTICATING"] = 1)] = "AUTHENTICATING";
  SocketState[(SocketState["READY"] = 2)] = "READY";
})(SocketState || (SocketState = {}));
var MessageType;
(function (MessageType) {
  MessageType[(MessageType["PING"] = 0)] = "PING";
  MessageType[(MessageType["CLIENT_UNAVAILABLE"] = 1)] = "CLIENT_UNAVAILABLE";
  MessageType[(MessageType["OFFER"] = 2)] = "OFFER";
  MessageType[(MessageType["ANSWER"] = 3)] = "ANSWER";
  MessageType[(MessageType["CANDIDATE"] = 4)] = "CANDIDATE";
})(MessageType || (MessageType = {}));
const clients = new Map();
const provider = RPC_PROVIDER_ADDRESS
  ? new ethers_1.JsonRpcProvider(RPC_PROVIDER_ADDRESS)
  : null;
const nodeWallet = new ethers_1.Wallet(IDENTITY, provider);
function processIdentify(client, data) {
  if (data.byteLength !== 52) return;
  client.identity = (0, ethers_1.hexlify)(data.slice(0, 20));
  client.state = SocketState.AUTHENTICATING;
  client.authMessage = (0, ethers_1.randomBytes)(24);
  nodeWallet.signMessage(data.slice(20)).then((signature) => {
    client.ws.send(
      (0, ethers_1.getBytes)(
        (0, ethers_1.concat)([client.authMessage, signature])
      )
    );
  });
}
function processAuthentication(client, data) {
  if (
    (0, ethers_1.verifyMessage)(
      client.authMessage,
      (0, ethers_1.hexlify)(data)
    ).toLowerCase() !== client.identity
  ) {
    client.ws.send(new Uint8Array([0]));
    return;
  }
  clients.set((0, ethers_1.hexlify)(client.identity), client);
  client.state = SocketState.READY;
  client.ws.send(new Uint8Array([1]));
}
function forward(messageType, from, data) {
  const client = clients.get((0, ethers_1.hexlify)(data.slice(0, 20)));
  if (
    !(client === null || client === void 0 ? void 0 : client.identity) ||
    client.state !== SocketState.READY
  ) {
    from.ws.send(
      (0, ethers_1.getBytes)(
        (0, ethers_1.concat)([
          new Uint8Array([MessageType.CLIENT_UNAVAILABLE]),
          data.slice(0, 20),
        ])
      )
    );
    return;
  }
  client.ws.send(
    (0, ethers_1.getBytes)(
      (0, ethers_1.concat)([
        new Uint8Array([messageType]),
        from.identity,
        data.slice(20),
      ])
    )
  );
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
    authMessage: new Uint8Array(),
    ws,
  };
  ws.on("open", function () {});
  ws.on("close", function () {
    client.state = SocketState.IDLE;
    if (client.identity) clients.delete((0, ethers_1.hexlify)(client.identity));
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

let requests = [];
const isEligibleForRequest = () => {
  const now = Math.round(new Date().getTime() / 1000);
  let hourlyRequestCount = 0;
  let cutoff = 0;
  for (let i = 0; i < requests.length; ++i) {
    if (requests[i] < now - 3600 && cutoff === 0) {
      cutoff = i;
    } else {
      hourlyRequestCount++;
    }
  }
  requests = requests.slice(cutoff);
  if (hourlyRequestCount > 10) {
    return false;
  }
  requests.push(now);
  return true;
};
if (RPC_PROVIDER_ADDRESS) {
  app.use(body_parser_1.default.raw());
  app.use((0, cors_1.default)());
  app.post("/identity", (req, res) => {
    if (req.body.byteLength !== 105) return res.send(400);
    const account = (0, ethers_1.hexlify)(
      new Uint8Array(req.body.slice(0, 20))
    );
    const identity = (0, ethers_1.hexlify)(
      new Uint8Array(req.body.slice(20, 40))
    );
    const signature = (0, ethers_1.hexlify)(new Uint8Array(req.body.slice(40)));
    if (
      (0, ethers_1.verifyMessage)(
        (0, ethers_1.getBytes)((0, ethers_1.concat)([account, identity])),
        signature
      ).toLowerCase() !== (0, ethers_1.hexlify)(account) ||
      !isEligibleForRequest()
    )
      return res.send(400);
    const { v, r, s } = ethers_1.Signature.from(signature);
    const contract = new ethers_1.Contract(CONTRACT_ADDRESS, ABI, nodeWallet);
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
}
console.log(`up & running on port ${PORT}`);
