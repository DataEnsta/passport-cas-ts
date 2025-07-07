"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CasStrategy = void 0;
const axios_1 = __importDefault(require("axios"));
const xml2js_1 = __importDefault(require("xml2js"));
const passport_1 = __importDefault(require("passport"));
const XML_PARSE_OPTIONS = {
    trim: true,
    normalize: true,
    explicitArray: false,
    tagNameProcessors: [
        xml2js_1.default.processors.normalize,
        xml2js_1.default.processors.stripPrefix,
    ],
};
class CasStrategy extends passport_1.default.Strategy {
    name = "cas";
    verify;
    config;
    errorLogger;
    debugLogger;
    constructor(verify, options, errorLogger, debugLogger) {
        super();
        this.verify = verify;
        this.config = { ...options };
        this.errorLogger = errorLogger;
        this.debugLogger = debugLogger;
    }
    logError = (msg, err) => {
        if (this.errorLogger) {
            this.errorLogger(msg, err);
        }
    };
    logDebug = (msg) => {
        if (this.debugLogger) {
            this.debugLogger(msg);
        }
    };
    async authenticate(req) {
        if (req.query.RelayState) {
            this.logDebug("RelayState present, logging out");
            return this.logout(req);
        }
        const service = this.getReqService(req);
        this.logDebug(`Extracted service: ${service}`);
        const ticket = req.query.ticket;
        if (!ticket) {
            this.logDebug("No ticket provided, starting login process");
            const redirectURL = new URL(this.config.loginRoute, this.config.base);
            redirectURL.searchParams.set("service", service);
            return this.redirect(redirectURL.toString());
        }
        this.logDebug(`Got ticket ${ticket}, starting validation process`);
        const target = new URL(this.config.validateRoute, this.config.base);
        target.searchParams.set("ticket", ticket);
        target.searchParams.set("service", service);
        const res = await axios_1.default.get(target.toString());
        if (res.status == 200) {
            this.logDebug(`Got info: ${res.data}`);
            this.validate(res.data);
        }
        else {
            const err = res.statusText;
            this.logError("Failed to validate ticket", err);
            return this.fail(new Error(err));
        }
    }
    logout(req) {
        req.logout((err) => {
            if (err) {
                this.logError("Failed to log request out", err);
            }
        });
        const redirectURL = new URL(this.config.logoutRoute, this.config.base);
        redirectURL.searchParams.set("_eventId", "next");
        redirectURL.searchParams.set("RelayState", req.query.RelayState);
        return this.redirect(redirectURL.toString());
    }
    getReqService(req) {
        const url = new URL(req.originalUrl, this.config.serverUrl);
        url.searchParams.delete("ticket");
        return url.toString();
    }
    validate(body) {
        const done = this.onceVerified.bind(this);
        xml2js_1.default.parseString(body, XML_PARSE_OPTIONS, (err, result) => {
            if (err || !result) {
                return done(new Error("Bad response from server"), null);
            }
            if (result.serviceresponse?.authenticationfailure) {
                return done(new Error("Authentication failed " +
                    result.serviceresponse.authenticationfailure.$?.code), null);
            }
            const success = result.serviceresponse?.authenticationsuccess;
            if (success) {
                this.logDebug("CAS validate: ticket ok, calling user verify function");
                this.logDebug("Got profile: " + JSON.stringify(success));
                return this.verify(success, done);
            }
            else {
                return done(new Error("Authentication failed"), null);
            }
        });
    }
    onceVerified = function (err, profile, info, challenge) {
        if (err) {
            this.logError("CAS verified callback error", err);
            return this.fail(challenge);
        }
        if (!profile) {
            this.logDebug("CAS verified callback error: invalid profile");
            this.logDebug(JSON.stringify(profile));
            return this.fail(challenge);
        }
        this.logDebug("CAS verified callback success");
        this.logDebug(JSON.stringify(profile));
        this.success(profile, info);
    };
}
exports.CasStrategy = CasStrategy;
//# sourceMappingURL=index.js.map