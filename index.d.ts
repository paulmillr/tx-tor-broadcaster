#!/usr/bin/env node
/// <reference types="node" resolution-mode="require"/>
/// <reference types="node" resolution-mode="require"/>
/// <reference types="node" resolution-mode="require"/>
import * as http from 'http';
import * as https from 'https';
import { Socket } from 'net';
declare type Headers = Record<string, string>;
declare type SocksOpts = {
    proxyHost: string;
    proxyPort: number;
    host: string;
    port: number;
    user?: string;
    password?: string;
};
export declare function socksv5(opts: SocksOpts): Promise<{
    socket: Socket;
    bndAddr: string | undefined;
    bndPort: number;
}>;
declare class Agent {
    private tor;
    private isSSL?;
    private reqId?;
    defaultPort: number;
    defaultProtocol: string;
    keepAlive: boolean;
    maxSockets: number;
    lastTs: number;
    userAgent: string;
    private agentId;
    constructor(tor: Tor, isSSL?: boolean | undefined, reqId?: string | undefined);
    addRequest(req: http.ClientRequest & {
        _last?: boolean;
        _hadError?: boolean;
    }, opt: http.RequestOptions | https.RequestOptions): Promise<void>;
    freeSocket(socket: Socket): void;
    resetId(): void;
}
export interface TorOptions {
    socksHost?: string;
    socksPort?: number;
    retryLimit?: number;
}
export declare class Tor {
    opt: Required<TorOptions>;
    readonly enabled: boolean;
    agentCache: Record<string, Agent>;
    constructor(opt?: TorOptions);
    getSocket(host: string, port: number, opt?: {
        ssl?: boolean;
        ssl_servername?: string;
        reqId?: string;
        rejectUnauthorized?: boolean;
    }): Promise<Socket>;
    private getAgent;
    private fetchReq;
    fetch(url: string, opt?: {
        type?: 'json' | 'text' | 'bytes';
        expectStatusCode?: number;
        data?: object;
        reqId?: string;
        retry_status?: number[];
        headers?: Headers;
    }): Promise<any>;
}
export declare class Broadcaster {
    readonly network: string;
    readonly tx: string;
    private tor;
    private sites;
    constructor(network: string, tx: string, opts: TorOptions);
    getIP(): Promise<any>;
    broadcast(): Promise<{
        txId: any;
        host: string;
    } | undefined>;
}
export {};
//# sourceMappingURL=index.d.ts.map