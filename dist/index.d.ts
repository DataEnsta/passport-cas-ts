import express from "express";
import passport, { StrategyFailure } from "passport";
export interface CasAuthenticationSuccess<Attributes> {
    user: string;
    attributes: Attributes;
}
export type VerifyCallback<Attributes> = (profile: CasAuthenticationSuccess<Attributes>, done: VerifiedCallback) => void;
export type VerifiedCallback = (err: any, profile: object | null, info?: object, challenge?: StrategyFailure | string | number) => void;
export interface CasOptions {
    base: string;
    loginRoute: string;
    validateRoute: string;
    logoutRoute: string;
    serverUrl: string;
}
type ErrorLoggingFunction = (msg: string, err: any) => void;
type LoggingFunction = (msg: string) => void;
export declare class CasStrategy<Attributes> extends passport.Strategy {
    readonly name: string;
    private readonly verify;
    private readonly config;
    private readonly errorLogger;
    private readonly debugLogger;
    constructor(verify: VerifyCallback<Attributes>, options: CasOptions, errorLogger?: ErrorLoggingFunction, debugLogger?: LoggingFunction);
    private logError;
    private logDebug;
    authenticate(req: express.Request): Promise<void>;
    private logout;
    private getReqService;
    private validate;
    private onceVerified;
}
export {};
