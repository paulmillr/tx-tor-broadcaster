# tx-tor-broadcaster

CLI utility that broadcasts BTC, ETH, SOL, ZEC & XMR transactions through [TOR](https://www.torproject.org) using public block explorers.

Provides a great degree of anonymity for your transactions.

Ensures no traffic is passed outside TOR, including DNS requests. Uses one small dependency which
provides list of popular user agents. See [fingerprinting](#fingerprinting) section for additional information.

## Usage

> npm install -g tx-tor-broadcaster

The command line interface is simple: call `txtor <NET> <TX>` command through terminal.

You must have Tor or Tor Browser up & running.

You can specify a few options via env variables, if needed:

- `TOR_HOST=192.168.2.5 txtor zec <tx>`; default is `127.0.0.1`
- `TOR_SOCKS_PORT=9051 txtor bch <tx>`; default is `9050` (`9150` should be used for Tor Browser)
- `TOR_RETRY_LIMIT=2 txtor sol <tx>`; default is `10`

```sh
txtor
# Usage: txtor <NET> <TX>
# NET: btc, eth, sol, zec, xmr, bch

txtor btc 0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000

txtor eth 0xf86c0a8502540be400825208944bbeeb066ed09b7aed07bf39eee0460dfa261520880de0b6b3a7640000801ca0f3ae52c1ef3300f44df0bcfd1341c232ed6134672b16e35699ae3f5fe2493379a023d23d2955a239dd6f61c4e8b2678d174356ff424eac53da53e17706c43ef871

txtor sol 4vC38p4bz7XyiXrk6HtaooUqwxTWKocf45cstASGtmrD398biNJnmTcUCVEojE7wVQvgdYbjHJqRFZPpzfCQpmUN
```

Node.js API:

```js
import { Broadcaster } from 'tx-tor-broadcaster';
const br = new Broadcaster(net, tx); // , opts = { socksHost, socksPort, retryLimit }
console.log(`${bold}TOR exit IP:${reset}`, await br.getIP());
const res = await br.broadcast();
if (res) console.log(`${green}${bold}Published${reset} (${res.host}): ${res.txId}`);
```

## Fingerprinting

Fingerprinting is an algorithm that allows to uniquely identify user within the global dataset.
For example, if you are using obscure old browser for everything, it's easy to
identify you within millions of users.

The app uses popular user agents [(package)](https://github.com/paulmillr/popular-user-agents) to
populate `User-Agent` header. If more than 120 days have passed since the dependency was last updated,
the package will stop working.

This mitigates only one variable. There are many others:

- Headers
    - `Accept`: e.g. `text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
    - `Accept-Encoding`: compression support `gzip, deflate, br`
    - `Accept-Language`: OS language
- TLS/SSL settings; indicating supported...
    - TLS protocols e.g. 1.3, 1.2
    - HTTP versions e.g. HTTP2, HTTP3
    - cipher suites e.g. `TLS_AES_256_GCM_SHA384` or `TLS_CHACHA20_POLY1305_SHA256`
    - named groups e.g. `x25519, secp256r1, x448, secp521r1, secp384r1`
- Network/TCP settings, possibly MTU/Nagle algorithm status

It has been decided the best way to go is not copying full browser behavior,
but instead, just setting the `User-Agent` header; to ensure Cloudflare is bypassed properly.

Since there are tens of variables that can affect fingerprint calculation,
it's non-trivial to set all of them properly. Not only that, we'll need to
update the params with every browser update. And we'll still probably
miss some minor detail.

- Let's say there are 1000 people who send TX through Tor using popular browser User Agent
- Out of them, only 100 will set additional headers like `Accept-Language`. Many of them
  will send different information in headers; some will support Enconding, some will not
- So, the more we mimic a particular browser, the more we increase our fingerprinting vector

To view the data you're leaving, check out
[httpbin](http://httpbin.org/headers), [httpbin ssl](https://httpbin.org/headers),
[browserleaks](https://browserleaks.com/ssl) and [valdikss](http://witch.valdikss.org.ru).

## License

MIT License (c) 2022 Paul Miller (https://paulmillr.com)
