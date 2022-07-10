#!/usr/bin/env node
import { createHash } from 'crypto';
import { realpathSync } from 'fs';
import * as http from 'http';
import * as https from 'https';
import { isIPv4, Socket } from 'net';
import { connect as tlsConnect } from 'tls';
import * as userAgents from 'popular-user-agents';
const SITE_TIMEOUT = 10 * 1000; // 10 seconds
const bold = '\x1b[1m';
const reset = '\x1b[0m';
const red = '\x1b[31m';
const green = '\x1b[32m';
const DEFAULTS = { host: '127.0.0.1', port: 9050, retryLimit: 10 };
function utf8ToBytes(string) {
    return new TextEncoder().encode(string);
}
function bytesToUtf8(bytes) {
    return new TextDecoder().decode(bytes);
}
function sha256(buf) {
    return createHash('sha256').update(buf).digest('hex');
}
function isCloudflare(text) {
    return text.includes('Cloudflare');
}
function shuffle(arr) {
    return arr
        .slice()
        .map((value) => ({ value, sorter: Math.random() }))
        .sort((a, b) => a.sorter - b.sorter)
        .map(({ value }) => value);
}
function detectType(b, type) {
    if (!type || type === 'text' || type === 'json') {
        try {
            let text = new TextDecoder('utf8', { fatal: true }).decode(b);
            if (type === 'text')
                return text;
            try {
                return JSON.parse(text);
            }
            catch (err) {
                if (type === 'json')
                    throw err;
                return text;
            }
        }
        catch (err) {
            if (type === 'text' || type === 'json')
                throw err;
        }
    }
    return b;
}
// Simple synchronyous socket interface via async/await (instead of callback abomination)
class SimpleSocket {
    constructor(socket) {
        this.socket = socket;
        this.buf = Buffer.from([]);
        // Create closures here, so we can remove on end
        this.onData = (data) => {
            this.buf = Buffer.concat([this.buf, data]);
            this.process();
        };
        this.onError = (err) => {
            this.err = err;
            if (!this.wait)
                return;
            this.wait.reject(this.err);
            this.wait = undefined;
        };
        this.onClose = () => {
            this.err = new Error('EOF');
            if (this.wait)
                this.wait.reject(this.err);
        };
        socket.on('data', this.onData).on('error', this.onError).on('close', this.onClose);
    }
    process() {
        if (!this.wait)
            return;
        const { resolve, len } = this.wait;
        if (len > this.buf.length)
            return;
        const buf = this.buf.slice(0, len);
        this.buf = this.buf.slice(len);
        this.wait = undefined;
        resolve(buf);
    }
    connect(host, port) {
        return new Promise((resolve, reject) => {
            if (this.wait)
                return reject(new Error('Socket already awaits read'));
            this.wait = { len: 0, resolve: resolve, reject };
            this.socket.connect({ host, port }, () => this.process());
        });
    }
    readBytes(len) {
        return new Promise((resolve, reject) => {
            if (this.err)
                reject(this.err);
            if (this.wait)
                reject(new Error('Socket already awaits read'));
            this.wait = { len, resolve, reject };
            this.process();
        });
    }
    write(buf) {
        this.socket.write(buf);
    }
    async readByte() {
        return (await this.readBytes(1))[0];
    }
    end() {
        // pause && unshift to save any left data (since there is no onData handler)
        // Most servers (http for example) won't send anything at this point
        this.socket.pause();
        this.socket
            .removeListener('data', this.onData)
            .removeListener('error', this.onError)
            .removeListener('close', this.onClose);
        this.socket.unshift(this.buf);
    }
}
// Small socks client
const SOCKS_VER = 0x05;
const AUTH_VER = 0x01;
var Auth;
(function (Auth) {
    Auth[Auth["None"] = 0] = "None";
    Auth[Auth["UserPass"] = 2] = "UserPass";
})(Auth || (Auth = {}));
var CMD;
(function (CMD) {
    CMD[CMD["CONNECT"] = 1] = "CONNECT";
})(CMD || (CMD = {}));
var ATYP;
(function (ATYP) {
    ATYP[ATYP["IPv4"] = 1] = "IPv4";
    ATYP[ATYP["NAME"] = 3] = "NAME";
})(ATYP || (ATYP = {}));
var REP;
(function (REP) {
    REP[REP["SUCCESS"] = 0] = "SUCCESS";
    REP[REP["EGENFAIL"] = 1] = "EGENFAIL";
    REP[REP["EACCES"] = 2] = "EACCES";
    REP[REP["ENETUNREACH"] = 3] = "ENETUNREACH";
    REP[REP["EHOSTUNREACH"] = 4] = "EHOSTUNREACH";
    REP[REP["ECONNREFUSED"] = 5] = "ECONNREFUSED";
    REP[REP["ETTLEXPIRED"] = 6] = "ETTLEXPIRED";
    REP[REP["ECMDNOSUPPORT"] = 7] = "ECMDNOSUPPORT";
    REP[REP["EATYPNOSUPPORT"] = 8] = "EATYPNOSUPPORT";
})(REP || (REP = {}));
// Micro-socks client
export async function socksv5(opts) {
    let sock = new SimpleSocket(new Socket());
    await sock.connect(opts.proxyHost, opts.proxyPort);
    // Auth
    if (opts.user || opts.password) {
        // REQ: [SOCKS_VER, NMETHODS=1, METHOD]
        sock.write(Buffer.from([SOCKS_VER, 0x01, Auth.UserPass]));
        // RESP: [SOCKS_VER, AUTH_METHOD]
        if ((await sock.readByte()) !== SOCKS_VER)
            throw new Error('Wrong socks version');
        if ((await sock.readByte()) !== Auth.UserPass)
            throw new Error('Wrong socks method');
        const user = utf8ToBytes(opts.user || '');
        const password = utf8ToBytes(opts.password || '');
        // Send auth request
        // [VER, USER_LEN, USER, PASS_LEN, PASS]
        sock.write(Buffer.concat([
            Buffer.from([0x01, user.length]),
            user,
            Buffer.from([password.length]),
            password,
        ]));
        // RESP: [AUTH_VER, STATUS]
        if ((await sock.readByte()) !== AUTH_VER)
            throw new Error('Unsupported auth version');
        if ((await sock.readByte()) !== 0x00)
            throw new Error('Authentication failed');
    }
    else {
        // REQ: [SOCKS_VER, NMETHODS=1, AUTH_METHOD]
        sock.write(Buffer.from([SOCKS_VER, 0x01, Auth.None]));
        // RESP: [SOCKS_VER, AUTH_METHOD]
        if ((await sock.readByte()) !== SOCKS_VER)
            throw new Error('Wrong socks version');
        if ((await sock.readByte()) !== Auth.None)
            throw new Error('Wrong socks method');
    }
    // Actual request
    // REQ: [VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT]
    const portBuf = Buffer.alloc(2);
    portBuf.writeUInt16BE(opts.port, 0);
    if (isIPv4(opts.host)) {
        sock.write(Buffer.from([
            SOCKS_VER,
            CMD.CONNECT,
            0x00,
            ATYP.IPv4,
            // Convert ipv4 to bytes (BE)
            ...opts.host.split('.', 4).map((i) => +i),
            ...Array.from(portBuf),
        ]));
    }
    else {
        const addr = utf8ToBytes(opts.host);
        sock.write(Buffer.from([
            SOCKS_VER,
            CMD.CONNECT,
            0x00,
            ATYP.NAME,
            addr.length,
            ...Array.from(addr),
            ...Array.from(portBuf),
        ]));
    }
    // Parse reply
    // RESP: [VER, REP, RSV, ATYP, DNB.ADDR, BND.PORT]
    if ((await sock.readByte()) !== SOCKS_VER)
        throw new Error('Wrong socks version');
    const status = await sock.readByte();
    if (status !== REP.SUCCESS)
        throw new Error(REP[status] || 'EUNKNOWN');
    await sock.readByte(); // Skip RSV (reserved) field
    const atyp = await sock.readByte();
    let bndAddr;
    if (atyp === ATYP.IPv4)
        bndAddr = (await sock.readBytes(4)).join('.');
    else if (atyp === ATYP.NAME)
        bndAddr = bytesToUtf8(await sock.readBytes(await sock.readByte()));
    const bndPortBuf = await sock.readBytes(2);
    // U16BE
    const bndPort = (bndPortBuf[0] << 8) | bndPortBuf[1];
    sock.end();
    return { socket: sock.socket, bndAddr, bndPort };
}
class Agent {
    constructor(tor, isSSL, reqId) {
        this.tor = tor;
        this.isSSL = isSSL;
        this.reqId = reqId;
        this.keepAlive = false;
        this.maxSockets = 1;
        this.tor = tor;
        this.defaultPort = isSSL ? 443 : 80;
        this.defaultProtocol = isSSL ? 'https' : 'http';
        this.userAgent = userAgents.random();
        this.agentId = 0;
        this.lastTs = Date.now();
    }
    async addRequest(req, opt) {
        this.lastTs = Date.now();
        const onError = (err) => {
            if (req._hadError)
                return;
            req.emit('error', err);
            req._hadError = true;
        };
        let timedOut = false;
        let timeoutId;
        timeoutId = setTimeout(() => {
            timeoutId = undefined;
            timedOut = true;
            const err = new Error('Timeout');
            err.code = 'ETIMEOUT';
            onError(err);
        }, SITE_TIMEOUT);
        if (!opt.host || !Number(opt.port))
            throw new Error(`Agent: wrong host (${opt.host}) or port (${opt.port})`);
        try {
            const socket = await this.tor.getSocket(opt.host, Number(opt.port), {
                ssl: this.isSSL,
                ssl_servername: opt.servername,
                reqId: `${this.reqId}_${this.agentId}`,
            });
            // Check for timeouts
            if (timedOut)
                return;
            timeoutId = timeoutId && clearTimeout(timeoutId);
            socket.once('free', () => this.freeSocket(socket));
            req.onSocket(socket);
        }
        catch (err) {
            if (timedOut)
                return;
            timeoutId = timeoutId && clearTimeout(timeoutId);
            onError(err);
        }
    }
    freeSocket(socket) {
        socket.destroy();
    }
    resetId() {
        this.agentId++;
        this.userAgent = userAgents.random();
    }
}
export class Tor {
    constructor(opt = {}) {
        this.enabled = true;
        this.agentCache = {};
        this.opt = {
            socksHost: opt.socksHost || DEFAULTS.host,
            socksPort: opt.socksPort || DEFAULTS.port,
            retryLimit: opt.retryLimit || DEFAULTS.retryLimit,
        };
    }
    async getSocket(host, port, opt = {}) {
        let { socket } = await socksv5({
            proxyHost: this.opt.socksHost,
            proxyPort: this.opt.socksPort,
            // Tor assigns exit ip based on hash of username.
            user: sha256(`${host}_${port}_${opt.reqId}`),
            host,
            port,
        });
        // For http/https it is safe to resume here, server won't send anything yet.
        socket.resume();
        if (opt.ssl)
            socket = tlsConnect({
                socket,
                servername: opt.ssl_servername || host,
                rejectUnauthorized: opt.rejectUnauthorized,
            });
        return socket;
    }
    getAgent(_url, reqId) {
        const isSSL = _url.startsWith('https');
        const parsed = new URL(_url);
        let host = parsed.hostname || parsed.host;
        if (!host)
            throw new Error(`empty host: ${_url}`);
        host += isSSL ? '_https' : '_http';
        return new Agent(this, isSSL, reqId);
    }
    fetchReq(url, opt = {}) {
        const lib = url.startsWith('https') ? https : http;
        return new Promise((resolve, reject) => {
            let req = lib.request(url, opt, (res) => {
                res.on('error', reject);
                return (async () => {
                    let buf = [];
                    for await (const chunk of res)
                        buf.push(Uint8Array.from(chunk));
                    return resolve([res, Uint8Array.from(Buffer.concat(buf))]);
                })();
            });
            req.on('error', reject);
            if (opt.body)
                req.write(opt.body);
            req.on('error', reject);
            req.end();
        });
    }
    async fetch(url, opt = {}) {
        const { retryLimit } = this.opt;
        let retry = 0;
        let status;
        const agent = this.getAgent(url, opt.reqId);
        let reqOpt = {
            method: 'GET',
            agent,
            headers: { ...opt.headers, 'User-Agent': agent.userAgent },
        };
        if (opt.type === 'json')
            reqOpt.headers['Content-Type'] = 'application/json';
        if (opt.data) {
            reqOpt.method = 'POST';
            reqOpt.body = opt.type == 'json' ? JSON.stringify(opt.data) : opt.data;
        }
        for (retry = 0; retry < retryLimit; retry++) {
            let [res, data] = await this.fetchReq(url, reqOpt);
            status = Number(res.statusCode);
            // Cloudflare returns 403 on catpcha
            const custom_retry = opt.retry_status && opt.retry_status.includes(status);
            if ((status === 403 || status === 503 || custom_retry) && retry < retryLimit - 1) {
                let text = bytesToUtf8(data);
                if (isCloudflare(text) || status === 503 || custom_retry) {
                    if (retry === retryLimit - 2)
                        throw new Error('Cloudflare :(');
                    agent.resetId();
                    continue;
                }
            }
            if (opt.expectStatusCode && res.statusCode !== opt.expectStatusCode)
                throw new Error(`Status Code: ${res.statusCode}`);
            // If we expect json, but cloudflare send 200 OK page
            try {
                return detectType(data, opt.type);
            }
            catch (e) {
                if (isCloudflare(bytesToUtf8(data))) {
                    if (retry === retryLimit - 2)
                        throw new Error('Cloudflare :(');
                    agent.resetId();
                    continue;
                }
            }
        }
        throw new Error('fetch: too much retries');
    }
}
async function blockchair(tor, net, tx) {
    const FULLNAME_MAP = {
        btc: 'bitcoin',
        bch: 'bitcoin-cash',
        eth: 'ethereum',
        zec: 'zcash',
        xmr: 'monero',
    };
    const res = await tor.fetch(`https://api.blockchair.com/${FULLNAME_MAP[net]}/push/transaction?data=${tx}`, {
        reqId: tx,
        type: 'json',
    });
    if (res.data && res.data.error)
        throw new Error(res.data.error);
    if (res.context && res.context.error)
        throw new Error(res.context.error);
    return res.data.transaction_hash;
}
async function sochain(tor, net, tx) {
    const res = await tor.fetch(`https://sochain.com/api/v2/send_tx/${net.toUpperCase()}`, {
        reqId: tx,
        type: 'json',
        data: { tx_hex: tx },
    });
    if (res.status === 'success')
        return res.data.txid;
    if (res.status === 'fail')
        throw new Error(JSON.stringify(res.data));
}
const etherscan = (key, headers) => async function etherscan(tor, net, tx) {
    const res = await tor.fetch(`https://api.etherscan.io/api?module=proxy&action=eth_sendRawTransaction&hex=${tx}&apikey=${key}`, { reqId: tx, type: 'json', headers });
    if (res.message === 'NOTOK')
        throw new Error(`status=${res.status}: ${res.result}`);
    if (res.error && res.error.message)
        throw new Error(`status=${res.error.code}: ${res.error.message}`);
    else
        return res.result;
};
const web3 = (url, headers) => async function web3(tor, net, tx) {
    const res = await tor.fetch(url, {
        reqId: tx,
        type: 'json',
        headers,
        data: { method: 'eth_sendRawTransaction', params: [tx], id: 0, jsonrpc: '2.0' },
    });
    if (res.error && res.error.message)
        throw new Error(res.error.message);
    return res.result;
};
const blockbook = (net, url, headers) => async function blockbook(tor, net, tx) {
    const res = await tor.fetch(`${url}/v2/sendtx/${tx}`, { reqId: tx, type: 'json', headers });
    if (res.error)
        throw new Error(res.error);
    return res.result;
};
const sol = (url, headers) => async function solana(tor, net, tx) {
    const res = await tor.fetch(url, {
        reqId: tx,
        type: 'json',
        headers,
        data: {
            method: 'sendTransaction',
            params: [tx, { encoding: 'base64' }],
            id: 0,
            jsonrpc: '2.0',
        },
    });
    if (res.error && res.error.message)
        throw new Error(res.error.message);
    return res.result;
};
function _atob(stre) {
    return Buffer.from(stre, 'base64').toString();
}
// The keys were found on the internet in public code. We won't want to use our own keys,
// to decrease fingerprinting vector
const registry = {
    btc: [blockchair, sochain, blockbook('btc', 'https://btc1.trezor.io/api', {})],
    eth: [
        blockchair,
        etherscan(_atob('VURKVzNBUlhXTjlFSE1URlVBMkZXNFYxS0E3UVpHQUdDQg=='), {
            Origin: 'https://etherscan.io',
            Referer: 'https://etherscan.io/',
        }),
        web3('https://node1.web3api.com/', {
            Origin: 'https://etherscan.io',
            Referer: 'https://etherscan.io/',
        }),
        web3('https://nodes.mewapi.io/rpc/eth', {
            Origin: 'https://www.myetherwallet.com',
        }),
        web3('https://mainnet.infura.io/v3/' + _atob('MmU1YmQyYmEwMzhkNGUzZjk2OWE1NmYyZWFkMDc0Y2E='), {
            Origin: 'https://www.myetherwallet.com',
        }),
        blockbook('eth', 'https://eth1.trezor.io/api', {}),
    ],
    bch: [blockchair, blockbook('bch', 'https://bch1.trezor.io/api', {})],
    xmr: [blockchair],
    zec: [blockchair, sochain, blockbook('zec', 'https://zec1.trezor.io/api', {})],
    sol: [
        sol('https://explorer-api.mainnet-beta.solana.com/', { Origin: 'https://explorer.solana.com' }),
    ],
};
export class Broadcaster {
    constructor(network, tx, opts) {
        this.network = network;
        this.tx = tx;
        // validate network
        if (!registry.hasOwnProperty(network))
            throw new Error(`Network ${network} is not supported`);
        const fns = registry[network];
        if (!Array.isArray(fns) || !fns.length) {
            throw new Error(`No valid broadcasters for network ${network}`);
        }
        this.sites = shuffle(fns);
        this.tor = new Tor(opts);
    }
    // reqId is not sent to an external server. It is only used to select Tor circuit,
    // so different txs will use different exit nodes.
    async getIP() {
        const res = await this.tor.fetch('http://httpbin.org/ip', { reqId: this.tx });
        return res.origin;
    }
    async broadcast() {
        for (let fn of this.sites) {
            const { name: host } = fn;
            try {
                const txId = await fn(this.tor, this.network, this.tx);
                return { txId, host };
            }
            catch (e) {
                console.log(`${red}${bold}Error${reset} (${host}): ${e}`);
            }
        }
    }
}
async function main() {
    const { TOR_HOST, TOR_SOCKS_PORT, TOR_RETRY_LIMIT } = process.env;
    const { argv } = process;
    const [filename, net, tx] = argv.slice(1);
    if (import.meta.url !== `file://${realpathSync(filename)}`)
        return;
    if (argv.length !== 4 || !(net in registry) || !tx) {
        return console.log(`Usage: txtor <NET> <TX>\nNET: ${Object.keys(registry).join(', ')}`);
    }
    const socksPort = Number.parseInt(TOR_SOCKS_PORT || '');
    const retryLimit = Number.parseInt(TOR_RETRY_LIMIT || '');
    const br = new Broadcaster(net, tx, { socksHost: TOR_HOST, socksPort, retryLimit });
    console.log(`${bold}TOR exit IP:${reset}`, await br.getIP());
    const res = await br.broadcast();
    if (res)
        console.log(`${green}${bold}Published${reset} (${res.host}): ${res.txId}`);
}
main();
