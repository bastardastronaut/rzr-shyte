"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const path_1 = __importDefault(require("path"));
exports.default = (app, appPath) => {
    app.use(express_1.default.static(appPath));
    // try * to enable routing
    app.get("/", (req, res) => {
        res.sendFile(path_1.default.join(`${appPath}/index.html`));
    });
};
