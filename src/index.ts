/**
 * index.ts
 * =========
 *
 * In this file is defined a `passport` strategy for a CAS
 * ({@link https://en.wikipedia.org/wiki/Central_Authentication_Service|Central Authentication Service}).
 *
 * This strategy is meant to be used with `passport` to authenticate users using an external CAS.
 *
 */

import axios from "axios";
import xml2js from "xml2js";
import express from "express";
import passport, { StrategyFailure } from "passport";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// User-provided hook on the authentication process
export type VerifyCallback<Attributes> = (
  profile: CasAuthenticationSuccess<Attributes>,
  done: VerifiedCallback,
) => void;

// Callback to be called by the user hook defined above
// Calling such a function with a truthy value for `err` make the authentication fail.
// Otherwise, if `err` is falsy, the authentication succeeds iff profile is truthy.
export type VerifiedCallback = (
  err: any,
  profile: object | null,
  info?: object,
  challenge?: StrategyFailure | string | number,
) => void;

// CAS server response after a validation request
interface CasServiceResponse<Attributes> {
  authenticationsuccess?: CasAuthenticationSuccess<Attributes>;
  authenticationfailure?: CasAuthenticationFailure;
}

// Successful CAS server response
export interface CasAuthenticationSuccess<Attributes> {
  user: string; // username
  // user metadata
  attributes: Attributes;
}

// Unsuccessful CAS server response
interface CasAuthenticationFailure {
  $?: {
    code?: any; // error code
  };
}

export interface CasOptions {
  base: string; // base URL of the CAS server
  loginRoute: string; // login route of the CAS server
  validateRoute: string; // validate route of the CAS server
  logoutRoute: string; // logout route of the CAS server
  serverUrl: string; // public URL of the server using CAS authentication
}

type ErrorLoggingFunction = (msg: string, err: any) => void;
type LoggingFunction = (msg: string) => void;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// CAS server validation response parsing options
const XML_PARSE_OPTIONS = {
  trim: true,
  normalize: true,
  explicitArray: false,
  tagNameProcessors: [
    xml2js.processors.normalize,
    xml2js.processors.stripPrefix,
  ],
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export class CasStrategy<Attributes> extends passport.Strategy {
  public readonly name: string = "cas"; // used by passport to identify the strategy
  private readonly verify: VerifyCallback<Attributes>; // user-provided hook to ultimately verify the authentication
  private readonly config: CasOptions;
  private readonly errorLogger: ErrorLoggingFunction | undefined;
  private readonly debugLogger: LoggingFunction | undefined;

  constructor(
    verify: VerifyCallback<Attributes>,
    options: CasOptions,
    errorLogger?: ErrorLoggingFunction,
    debugLogger?: LoggingFunction,
  ) {
    super();
    this.verify = verify;
    this.config = { ...options };
    this.errorLogger = errorLogger;
    this.debugLogger = debugLogger;
  }

  private logError: ErrorLoggingFunction = (msg: string, err: any) => {
    if (this.errorLogger) {
      this.errorLogger(msg, err);
    }
  };

  private logDebug: LoggingFunction = (msg: string) => {
    if (this.debugLogger) {
      this.debugLogger(msg);
    }
  };

  // See https://apereo.github.io/cas/6.6.x/images/cas_flow_diagram.png for details about the CAS authentication
  // workflow
  public async authenticate(req: express.Request) {
    // handle logout request
    if (req.query.RelayState) {
      this.logDebug("RelayState present, logging out");
      return this.logout(req);
    }

    const service = this.getReqService(req);
    this.logDebug(`Extracted service: ${service}`);
    const ticket = req.query.ticket;

    // If no ticket, then it is the first call. We redirect to login page, and it will call this code again with a
    // ticket
    if (!ticket) {
      this.logDebug("No ticket provided, starting login process");
      const redirectURL = new URL(this.config.loginRoute, this.config.base);
      redirectURL.searchParams.set("service", service);
      return this.redirect(redirectURL.toString());
    }

    // If there is a ticket, then we check it validity
    this.logDebug(`Got ticket ${ticket}, starting validation process`);
    const target = new URL(this.config.validateRoute, this.config.base);
    target.searchParams.set("ticket", ticket as string);
    target.searchParams.set("service", service);

    const res = await axios.get<string>(target.toString());
    if (res.status == 200) {
      // Check ticket validity when data has arrived
      this.logDebug(`Got info: ${res.data}`);
      this.validate(res.data);
    } else {
      // If the CAS server cannot be reached for some reason, make authentication fail
      const err = res.statusText;
      this.logError("Failed to validate ticket", err);
      return this.fail(new Error(err));
    }
  }

  // Logout handler in case the query had a `RelayState` parameter
  private logout(req: express.Request) {
    // logout locally
    req.logout((err: any) => {
      if (err) {
        this.logError("Failed to log request out", err);
      }
    });
    // request logout on the CAS server
    const redirectURL = new URL(this.config.logoutRoute, this.config.base);
    redirectURL.searchParams.set("_eventId", "next");
    redirectURL.searchParams.set("RelayState", req.query.RelayState as string);
    return this.redirect(redirectURL.toString());
  }

  // Extract the service of the request by removing the ticket parameter
  private getReqService(req: express.Request) {
    const url = new URL(req.originalUrl, this.config.serverUrl);
    url.searchParams.delete("ticket");
    return url.toString();
  }

  // Read the validation response to know whether the ticket is valid or not
  private validate(body: string) {
    const done: VerifiedCallback = this.onceVerified.bind(this);
    xml2js.parseString(
      body,
      XML_PARSE_OPTIONS,
      (
        err: Error | null,
        result: { serviceresponse?: CasServiceResponse<Attributes> },
      ): void => {
        if (err || !result) {
          // XML parsing failed
          return done(new Error("Bad response from server"), null);
        }
        if (result.serviceresponse?.authenticationfailure) {
          return done(
            new Error(
              "Authentication failed " +
                result.serviceresponse.authenticationfailure.$?.code,
            ),
            null,
          );
        }
        const success = result.serviceresponse?.authenticationsuccess;
        if (success) {
          this.logDebug(
            "CAS validate: ticket ok, calling user verify function",
          );
          this.logDebug("Got profile: " + JSON.stringify(success));
          // call user-provided hook before validating
          return this.verify(success, done);
        } else {
          return done(new Error("Authentication failed"), null);
        }
      },
    );
  }

  // Finish the authentication process (called by the user-provided verify function)
  private onceVerified: VerifiedCallback = function (
    this: CasStrategy<Attributes>,
    err,
    profile,
    info,
    challenge,
  ) {
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
