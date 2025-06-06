'use strict';
// a single connection

const dns         = require('node:dns');
const net         = require('node:net');
const os          = require('node:os');

// npm libs
const ipaddr      = require('ipaddr.js');
const config      = require('haraka-config');
const constants   = require('haraka-constants');
const net_utils   = require('haraka-net-utils');
const Notes       = require('haraka-notes');
const utils       = require('haraka-utils');
const { Address } = require('address-rfc2821');
const ResultStore = require('haraka-results');

// Haraka libs
const logger      = require('./logger');
const trans       = require('./transaction');
const plugins     = require('./plugins');
const rfc1869     = require('./rfc1869');
const outbound    = require('./outbound');

const states      = constants.connection.state;

const cfg = config.get('connection.ini', {
    booleans: [
        '-main.strict_rfc1869',
        '+main.smtputf8',
        '+headers.add_received',
        '+headers.show_version',
        '+headers.clean_auth_results',
    ]
});

const haproxy_hosts_ipv4 = [];
const haproxy_hosts_ipv6 = [];

for (const ip of cfg.haproxy.hosts) {
    if (!ip) continue;
    if (net.isIPv6(ip.split('/')[0])) {
        haproxy_hosts_ipv6.push([ipaddr.IPv6.parse(ip.split('/')[0]), parseInt(ip.split('/')[1] || 64)]);
    }
    else {
        haproxy_hosts_ipv4.push([ipaddr.IPv4.parse(ip.split('/')[0]), parseInt(ip.split('/')[1] || 32)]);
    }
}

class Connection {
    constructor (client, server, smtp_cfg) {
        this.client = client;
        this.server = server;

        this.local = {
            ip: null,
            port: null,
            host: net_utils.get_primary_host_name(),
            info: 'Haraka',
        };
        this.remote = {
            ip:   null,
            port: null,
            host: null,
            info: null,
            closed: false,
            is_private: false,
            is_local: false,
        };
        this.hello = {
            host: null,
            verb: null,
        };
        this.tls = {
            enabled: false,
            advertised: false,
            verified: false,
            cipher: {},
        };
        this.proxy = {
            allowed: false,
            ip: null,
            type: null,
            timer: null,
        };
        this.set('tls', 'enabled', (!!server.has_tls));

        this.current_data = null;
        this.current_line = null;
        this.state = states.PAUSE;
        this.encoding = 'utf8';
        this.prev_state = null;
        this.loop_code = null;
        this.loop_msg = null;
        this.uuid = utils.uuid();
        this.notes = new Notes();
        this.transaction = null;
        this.tran_count = 0;
        this.capabilities = null;
        this.early_talker = false;
        this.pipelining = false;
        this._relaying = false;
        this.esmtp = false;
        this.last_response = null;
        this.hooks_to_run = [];
        this.start_time = Date.now();
        this.last_reject = '';
        this.totalbytes = 0;
        this.rcpt_count = {
            accept:   0,
            tempfail: 0,
            reject:   0,
        };
        this.msg_count = {
            accept:   0,
            tempfail: 0,
            reject:   0,
        };
        this.results = new ResultStore(this);
        this.errors = 0;
        this.last_rcpt_msg = null;
        this.hook = null;
        if (cfg.headers.show_version) {
            this.local.info += `/${utils.getVersion(__dirname)}`;
        }
        Connection.setupClient(this);
    }
    static setupClient (self) {
        const ip = self.client.remoteAddress;
        if (!ip) {
            self.logdebug('setupClient got no IP address for this connection!');
            self.client.destroy();
            return;
        }

        const local_addr = self.server.address();
        self.set('local', 'ip', ipaddr.process(self.client.localAddress || local_addr.address).toString());
        self.set('local', 'port', (self.client.localPort || local_addr.port));
        self.results.add({name: 'local'}, self.local);

        self.set('remote', 'ip', ipaddr.process(ip).toString());
        self.set('remote', 'port', self.client.remotePort);
        self.results.add({name: 'remote'}, self.remote);

        self.lognotice( 'connect', {
            ip: self.remote.ip,
            port: self.remote.port,
            local_ip: self.local.ip,
            local_port: self.local.port
        });

        if (!self.client.on) return;

        const log_data = {ip: self.remote.ip}
        if (self.remote.host) log_data.host = self.remote.host

        self.client.on('end', () => {
            if (self.state >= states.DISCONNECTING) return;
            self.remote.closed = true;
            self.loginfo('client half closed connection', log_data);
            self.fail();
        });

        self.client.on('close', has_error => {
            if (self.state >= states.DISCONNECTING) return;
            self.remote.closed = true;
            self.loginfo('client dropped connection', log_data);
            self.fail();
        });

        self.client.on('error', err => {
            if (self.state >= states.DISCONNECTING) return;
            self.loginfo(`client connection error: ${err}`, log_data);
            self.fail();
        });

        self.client.on('timeout', () => {
            // FIN has sent, when timeout just destroy socket
            if (self.state >= states.DISCONNECTED) {
                self.client.destroy();
                self.loginfo(`timeout, destroy socket (state:${self.state})`)
                return;
            }
            if (self.state >= states.DISCONNECTING) return;
            self.respond(421, 'timeout', () => {
                self.fail('client connection timed out', log_data);
            });
        });

        self.client.on('data', data => {
            self.process_data(data);
        });

        const ha_list = net.isIPv6(self.remote.ip) ? haproxy_hosts_ipv6 : haproxy_hosts_ipv4;
        if (ha_list.some((element, index, array) => {
            return ipaddr.parse(self.remote.ip).match(element[0], element[1]);
        })) {
            self.proxy.allowed = true;
            // Wait for PROXY command
            self.proxy.timer = setTimeout(() => {
                self.respond(421, 'PROXY timeout',() => {
                    self.disconnect();
                });
            }, 30 * 1000);
        }
        else {
            plugins.run_hooks('connect_init', self);
        }
    }
    setTLS (obj) {
        this.set('hello', 'host', undefined);
        this.set('tls',   'enabled', true);
        for (const t of ['cipher','verified','verifyError','peerCertificate']) {
            if (obj[t] === undefined) continue;
            this.set('tls', t, obj[t]);
        }
        // prior to 2017-07, authorized and verified were both used. Verified
        // seems to be the more common and has the property updated in the
        // tls object. However, authorized has been up-to-date in the notes. Store
        // in both, for backwards compatibility.
        this.notes.tls = {
            authorized: obj.verified,   // legacy name
            authorizationError: obj.verifyError,
            cipher: obj.cipher,
            peerCertificate: obj.peerCertificate,
        }
    }
    set (prop_str, val) {
        if (arguments.length === 3) {
            prop_str = `${arguments[0]}.${arguments[1]}`;
            val = arguments[2];
        }

        const path_parts = prop_str.split('.');
        let loc = this;
        for (let i=0; i < path_parts.length; i++) {
            const part = path_parts[i];
            if (part === "__proto__" || part === "constructor") continue;

            // while another part remains
            if (i < (path_parts.length - 1)) {
                if (loc[part] === undefined) loc[part] = {};   // initialize
                loc = loc[part];   // descend
                continue;
            }

            // last part, so assign the value
            loc[part] = val;
        }

        // Set is_private, is_local automatically when remote.ip is set
        if (prop_str === 'remote.ip') {
            this.set('remote.is_local', net_utils.is_local_ip(this.remote.ip));
            if (this.remote.is_local) {
                this.set('remote.is_private', true);
            }
            else {
                this.set('remote.is_private', net_utils.is_private_ip(this.remote.ip));
            }
        }
    }
    get (prop_str) {
        return prop_str.split('.').reduce((prev, curr) => {
            return prev ? prev[curr] : undefined
        }, this)
    }
    set relaying (val) {
        if (this.transaction) {
            this.transaction._relaying = val;
        }
        else {
            this._relaying = val;
        }
    }
    get relaying () {
        if (this.transaction && '_relaying' in this.transaction) return this.transaction._relaying;
        return this._relaying;
    }
    process_line (line) {

        if (this.state >= states.DISCONNECTING) {
            if (logger.would_log(logger.LOGPROTOCOL)) {
                this.logprotocol(`C: (after-disconnect): ${this.current_line}`, {'state': this.state});
            }
            this.loginfo(`data after disconnect from ${this.remote.ip}`);
            return;
        }

        if (this.state === states.DATA) {
            if (logger.would_log(logger.LOGDATA)) {
                this.logdata(`C: ${line}`);
            }
            this.accumulate_data(line);
            return;
        }

        this.current_line = line.toString(this.encoding).replace(/\r?\n/, '');
        if (logger.would_log(logger.LOGPROTOCOL)) {
            this.logprotocol(`C: ${this.current_line}`, {'state': this.state});
        }

        // Check for non-ASCII characters
        /* eslint no-control-regex: 0 */
        if (/[^\x00-\x7F]/.test(this.current_line)) {
            // See if this is a TLS handshake
            const buf = Buffer.from(this.current_line.substr(0,3), 'binary');
            if (buf[0] === 0x16 && buf[1] === 0x03 &&
               (buf[2] === 0x00 || buf[2] === 0x01) // SSLv3/TLS1.x format
            ) {
                // Nuke the current input buffer to prevent processing further input
                this.current_data = null;
                this.respond(501, 'SSL attempted over a non-SSL socket');
                this.disconnect();
                return;
            }
            else if (this.hello.verb == 'HELO') {
                return this.respond(501, 'Syntax error (8-bit characters not allowed)');
            }
        }

        if (this.state === states.CMD) {
            this.state = states.PAUSE_SMTP;
            const matches = /^([^ ]*)( +(.*))?$/.exec(this.current_line);
            if (!matches) {
                return plugins.run_hooks('unrecognized_command',
                    this, [this.current_line]);
            }
            const cmd = matches[1];
            const method = `cmd_${cmd.toLowerCase()}`;
            const remaining = matches[3] || '';
            if (this[method]) {
                try {
                    this[method](remaining);
                }
                catch (err) {
                    if (err.stack) {
                        this.logerror(`${method} failed: ${err}`);
                        err.stack.split("\n").forEach(this.logerror);
                    }
                    else {
                        this.logerror(`${method} failed: ${err}`);
                    }
                    this.respond(421, "Internal Server Error", () => {
                        this.disconnect();
                    });
                }
            }
            else {
                // unrecognized command
                plugins.run_hooks('unrecognized_command', this, [ cmd, remaining ]);
            }
        }
        else if (this.state === states.LOOP) {
            // Allow QUIT
            if (this.current_line.toUpperCase() === 'QUIT') {
                this.cmd_quit();
            }
            else {
                this.respond(this.loop_code, this.loop_msg);
            }
        }
        else {
            throw new Error(`unknown state ${this.state}`);
        }
    }
    process_data (data) {
        if (this.state >= states.DISCONNECTING) {
            this.loginfo(`data after disconnect from ${this.remote.ip}`);
            return;
        }

        if (!this.current_data || !this.current_data.length) {
            this.current_data = data;
        }
        else {
            // Data left over in buffer
            const buf = Buffer.concat(
                [ this.current_data, data ],
                (this.current_data.length + data.length)
            );
            this.current_data = buf;
        }

        this._process_data();
    }
    _process_data () {
        // We *must* detect disconnected connections here as the state
        // only transitions to states.CMD in the respond function below.
        // Otherwise if multiple commands are pipelined and then the
        // connection is dropped; we'll end up in the function forever.
        if (this.state >= states.DISCONNECTING) return;

        let maxlength;
        if (this.state === states.PAUSE_DATA || this.state === states.DATA) {
            maxlength = cfg.max.data_line_length;
        }
        else {
            maxlength = cfg.max.line_length;
        }

        let offset;
        while (this.current_data && ((offset = utils.indexOfLF(this.current_data, maxlength)) !== -1)) {
            if (this.state === states.PAUSE_DATA) {
                return;
            }
            let this_line = this.current_data.slice(0, offset+1);
            // Hack: bypass this code to allow HAProxy's PROXY extension
            const proxyStart = this.proxy.allowed && /^PROXY /.test(this_line);
            if (this.state === states.PAUSE && proxyStart) {
                if (this.proxy.timer) clearTimeout(this.proxy.timer);
                this.state = states.CMD;
                this.current_data = this.current_data.slice(this_line.length);
                this.process_line(this_line);
            }
            // Detect early_talker but allow PIPELINING extension (ESMTP)
            else if ((this.state === states.PAUSE || this.state === states.PAUSE_SMTP) && !this.esmtp) {
                // Allow EHLO/HELO to be pipelined with PROXY
                if (this.proxy.allowed && /^(?:EH|HE)LO /i.test(this_line)) return;
                if (!this.early_talker) {
                    this_line = this_line.toString().replace(/\r?\n/,'');
                    this.logdebug('[early_talker]', { state: this.state, esmtp: this.esmtp, line: this_line });
                }
                this.early_talker = true;
                setImmediate(() => { this._process_data() });
                break;
            }
            else if ((this.state === states.PAUSE || this.state === states.PAUSE_SMTP) && this.esmtp) {
                let valid = true;
                const cmd = this_line.toString('ascii').slice(0,4).toUpperCase();
                switch (cmd) {
                    case 'RSET':
                    case 'MAIL':
                    case 'SEND':
                    case 'SOML':
                    case 'SAML':
                    case 'RCPT':
                        // These can be anywhere in the group
                        break;
                    default:
                        // Anything else *MUST* be the last command in the group
                        if (this_line.length !== this.current_data.length) {
                            valid = false;
                        }
                        break;
                }
                if (valid) {
                    // Valid PIPELINING
                    // We *don't want to process this yet otherwise the
                    // current_data buffer will be lost.  The respond()
                    // function will call this function again once it
                    // has reset the state back to states.CMD and this
                    // ensures that we only process one command at a
                    // time.
                    this.pipelining = true;
                    this.logdebug(`pipeline: ${this_line}`);
                }
                else {
                    // Invalid pipeline sequence
                    // Treat this as early talker
                    if (!this.early_talker) {
                        this.logdebug('[early_talker]', { state: this.state, esmtp: this.esmtp, line: this_line });
                    }
                    this.early_talker = true;
                    setImmediate(() => { this._process_data() });
                }
                break;
            }
            else {
                this.current_data = this.current_data.slice(this_line.length);
                this.process_line(this_line);
            }
        }

        if (this.current_data && (this.current_data.length > maxlength) &&
                (utils.indexOfLF(this.current_data, maxlength) === -1)) {
            if (this.state !== states.DATA && this.state !== states.PAUSE_DATA) {
                // In command mode, reject:
                this.client.pause();
                this.current_data = null;
                return this.respond(521, "Command line too long", () => {
                    this.disconnect();
                });
            }
            else {
                this.loginfo(`DATA line length (${this.current_data.length}) exceeds limit of ${maxlength} bytes`);
                this.transaction.notes.data_line_length_exceeded = true;
                const b = Buffer.concat([
                    this.current_data.slice(0, maxlength - 2),
                    Buffer.from("\r\n ", 'utf8'),
                    this.current_data.slice(maxlength - 2)
                ], this.current_data.length + 3);
                this.current_data = b;
                return this._process_data();
            }
        }
    }
    respond (code, msg, func) {
        let uuid = '';
        let messages;

        if (this.state === states.DISCONNECTED) {
            if (func) func();
            return;
        }
        // Check to see if DSN object was passed in
        if (typeof msg === 'object' && msg.constructor.name === 'DSN') {
            // Override
            code = msg.code;
            msg = msg.reply;
        }

        if (!Array.isArray(msg)) {
            messages = msg.toString().split(/\n/);
        }
        else {
            messages = msg.slice();
        }
        messages = messages.filter((msg2) => {
            return /\S/.test(msg2);
        });

        // Multiline AUTH PLAIN as in RFC-4954 page 8.
        if (code === 334 && !messages.length) {
            messages = [' '];
        }

        if (code >= 400) {
            this.last_reject = `${code} ${messages.join(' ')}`;
            if (cfg.uuid.deny_chars) {
                uuid = (this.transaction || this).uuid;
                if (cfg.uuid.deny_chars > 1) {
                    uuid = uuid.substr(0, cfg.uuid.deny_chars);
                }
            }
        }

        let mess;
        let buf = '';
        const hostname = os.hostname().split('.').shift();
        const _uuid = uuid ? `[${uuid}@${hostname}] ` : '';

        while ((mess = messages.shift())) {
            const line = `${code}${(messages.length ? "-" : " ")}${_uuid}${mess}`;
            this.logprotocol(`S: ${line}`);
            buf = `${buf}${line}\r\n`;
        }

        if (this.client.write === undefined) return buf;  // testing

        try {
            this.client.write(buf);
        }
        catch (err) {
            return this.fail(`Writing response: ${buf} failed: ${err}`);
        }

        // Store the last response
        this.last_response = buf;

        // Don't change loop state
        if (this.state !== states.LOOP) {
            this.state = states.CMD;
        }

        // Run optional closure before handling and further commands
        if (func) func();

        // Process any buffered commands (PIPELINING)
        this._process_data();
    }
    fail (err, err_data) {
        if (err) this.logwarn(err, err_data);
        this.hooks_to_run = [];
        this.disconnect();
    }
    disconnect () {
        if (this.state >= states.DISCONNECTING) return;
        this.state = states.DISCONNECTING;
        this.current_data = null; // don't process any more data we have already received
        this.reset_transaction(() => {
            plugins.run_hooks('disconnect', this);
        });
    }
    disconnect_respond () {
        const logdetail = {
            'ip': this.remote.ip,
            'rdns': ((this.remote.host) ? this.remote.host : ''),
            'helo': ((this.hello.host) ? this.hello.host : ''),
            'relay': (this.relaying ? 'Y' : 'N'),
            'early': (this.early_talker ? 'Y' : 'N'),
            'esmtp': (this.esmtp ? 'Y' : 'N'),
            'tls': (this.tls.enabled ? 'Y' : 'N'),
            'pipe': (this.pipelining ? 'Y' : 'N'),
            'errors': this.errors,
            'txns': this.tran_count,
            'rcpts': `${this.rcpt_count.accept}/${this.rcpt_count.tempfail}/${this.rcpt_count.reject}`,
            'msgs': `${this.msg_count.accept}/${this.msg_count.tempfail}/${this.msg_count.reject}`,
            'bytes': this.totalbytes,
            'lr': ((this.last_reject) ? this.last_reject : ''),
            'time': (Date.now() - this.start_time)/1000,
        };

        this.results.add({name: 'disconnect'}, {
            duration: (Date.now() - this.start_time)/1000,
        });
        this.lognotice('disconnect', logdetail);
        this.state = states.DISCONNECTED;
        this.client.end();
    }
    get_capabilities () {
        return [];
    }
    tran_uuid () {
        this.tran_count++;
        return `${this.uuid}.${this.tran_count}`;
    }
    reset_transaction (cb) {
        this.results.add({name: 'reset'}, {
            duration: (Date.now() - this.start_time)/1000,
        });
        if (this.transaction && this.transaction.resetting === false) {
            // Pause connection to allow the hook to complete
            this.pause();
            this.transaction.resetting = true;
            plugins.run_hooks('reset_transaction', this, cb);
        }
        else {
            this.transaction = null;
            if (cb) cb();
        }
    }
    reset_transaction_respond (retval, msg, cb) {
        if (this.transaction) {
            this.transaction.message_stream.destroy();
            this.transaction = null;
        }
        if (cb) cb();
        // Allow the connection to continue
        this.resume();
    }
    init_transaction (cb) {
        this.reset_transaction(() => {
            this.transaction = trans.createTransaction(this.tran_uuid(), cfg);
            // Catch any errors from the message_stream
            this.transaction.message_stream.on('error', (err) => {
                this.logcrit(`message_stream error: ${err.message}`);
                this.respond('421', 'Internal Server Error', () => {
                    this.disconnect();
                });
            });
            this.transaction.results = new ResultStore(this);
            if (cb) cb();
        });
    }
    loop_respond (code, msg) {
        if (this.state >= states.DISCONNECTING) return;
        this.state = states.LOOP;
        this.loop_code = code;
        this.loop_msg = msg;
        this.respond(code, msg);
    }
    pause () {
        if (this.state >= states.DISCONNECTING) return;
        this.client.pause();
        if (this.state !== states.PAUSE_DATA) this.prev_state = this.state;
        this.state = states.PAUSE_DATA;
    }
    resume () {
        if (this.state >= states.DISCONNECTING) return;
        this.client.resume();
        if (this.prev_state) {
            this.state = this.prev_state;
            this.prev_state = null;
        }
        setImmediate(() => this._process_data());
    }
    /////////////////////////////////////////////////////////////////////////////
    // SMTP Responses
    connect_init_respond (retval, msg) {
        // retval and message are ignored
        this.logdebug('running connect_init_respond');
        plugins.run_hooks('lookup_rdns', this);
    }
    lookup_rdns_respond (retval, msg) {
        switch (retval) {
            case constants.ok:
                this.set('remote', 'host', (msg || 'Unknown'));
                this.set('remote', 'info', (this.remote.info || this.remote.host));
                plugins.run_hooks('connect', this);
                break;
            case constants.deny:
                this.loop_respond(554, msg || "rDNS Lookup Failed");
                break;
            case constants.denydisconnect:
            case constants.disconnect:
                this.respond(554, msg || "rDNS Lookup Failed", () => {
                    this.disconnect();
                });
                break;
            case constants.denysoft:
                this.loop_respond(421, msg || "rDNS Temporary Failure");
                break;
            case constants.denysoftdisconnect:
                this.respond(421, msg || "rDNS Temporary Failure", () => {
                    this.disconnect();
                });
                break;
            default:
                // BUG: dns.reverse throws on invalid input (and sometimes valid
                // input nodejs/node#47847). Also throws when empty results
                try {
                    dns.reverse(this.remote.ip, (err, domains) => {
                        this.rdns_response(err, domains);
                    })
                }
                catch (err) {
                    this.rdns_response(err, []);
                }
        }
    }
    rdns_response (err, domains) {
        if (err) {
            switch (err.code) {
                case dns.NXDOMAIN:
                case dns.NOTFOUND:
                    this.set('remote', 'host', 'NXDOMAIN');
                    break;
                default:
                    this.set('remote', 'host', 'DNSERROR');
                    break;
            }
        }
        else {
            this.set('remote', 'host', (domains[0] || 'Unknown'));
            this.results.add({name: 'remote'}, this.remote);
        }
        this.set('remote', 'info', this.remote.info || this.remote.host);
        plugins.run_hooks('connect', this);
    }
    unrecognized_command_respond (retval, msg) {
        switch (retval) {
            case constants.ok:
                // response already sent, cool...
                break;
            case constants.next_hook:
                plugins.run_hooks(msg, this);
                break;
            case constants.deny:
                this.respond(500, msg || "Unrecognized command");
                break;
            case constants.denydisconnect:
            case constants.denysoftdisconnect:
                this.respond(retval === constants.denydisconnect ? 521 : 421, msg || "Unrecognized command", () => {
                    this.disconnect();
                });
                break;
            default:
                this.errors++;
                this.respond(500, msg || "Unrecognized command");
        }
    }
    connect_respond (retval, msg) {
        // RFC 5321 Section 4.3.2 states that the only valid SMTP codes here are:
        // 220 = Service ready
        // 554 = Transaction failed (no SMTP service here)
        // 421 = Service shutting down and closing transmission channel
        switch (retval) {
            case constants.deny:
                this.loop_respond(554, msg || "Your mail is not welcome here");
                break;
            case constants.denydisconnect:
            case constants.disconnect:
                this.respond(554, msg || "Your mail is not welcome here", () => {
                    this.disconnect();
                });
                break;
            case constants.denysoft:
                this.loop_respond(421, msg || "Come back later");
                break;
            case constants.denysoftdisconnect:
                this.respond(421, msg || "Come back later", () => {
                    this.disconnect();
                });
                break;
            default: {
                let greeting;
                if (cfg.message.greeting?.length) {
                    // RFC5321 section 4.2
                    // Hostname/domain should appear after the 220
                    greeting = [...cfg.message.greeting];
                    greeting[0] = `${this.local.host} ESMTP ${greeting[0]}`;
                    if (cfg.uuid.banner_chars) {
                        greeting[0] += ` (${this.uuid.substr(0, cfg.uuid.banner_chars)})`;
                    }
                }
                else {
                    greeting = `${this.local.host} ESMTP ${this.local.info} ready`;
                    if (cfg.uuid.banner_chars) {
                        greeting += ` (${this.uuid.substr(0, cfg.uuid.banner_chars)})`;
                    }
                }
                this.respond(220, msg || greeting);
            }
        }
    }
    get_remote (prop) {
        switch (this.remote[prop]) {
            case 'NXDOMAIN':
            case 'DNSERROR':
            case '':
            case undefined:
            case null:
                return `[${this.remote.ip}]`;
            default:
                return `${this.remote[prop]} [${this.remote.ip}]`;
        }
    }
    helo_respond (retval, msg) {
        switch (retval) {
            case constants.deny:
                this.respond(550, msg || "HELO denied", () => {
                    this.set('hello', 'verb', null);
                    this.set('hello', 'host', null);
                });
                break;
            case constants.denydisconnect:
                this.respond(550, msg || "HELO denied", () => {
                    this.disconnect();
                });
                break;
            case constants.denysoft:
                this.respond(450, msg || "HELO denied", () => {
                    this.set('hello', 'verb', null);
                    this.set('hello', 'host', null);
                });
                break;
            case constants.denysoftdisconnect:
                this.respond(450, msg || "HELO denied", () => {
                    this.disconnect();
                });
                break;
            default:
                // RFC5321 section 4.1.1.1
                // Hostname/domain should appear after 250
                this.respond(250, `${this.local.host} Hello ${this.get_remote('host')}, ${cfg.message.helo}`);
        }
    }
    ehlo_respond (retval, msg) {

        switch (retval) {
            case constants.deny:
                this.respond(550, msg || "EHLO denied", () => {
                    this.set('hello', 'verb', null);
                    this.set('hello', 'host', null);
                });
                break;
            case constants.denydisconnect:
                this.respond(550, msg || "EHLO denied", () => {
                    this.disconnect();
                });
                break;
            case constants.denysoft:
                this.respond(450, msg || "EHLO denied", () => {
                    this.set('hello', 'verb', null);
                    this.set('hello', 'host', null);
                });
                break;
            case constants.denysoftdisconnect:
                this.respond(450, msg || "EHLO denied", () => {
                    this.disconnect();
                });
                break;
            default: {
                // RFC5321 section 4.1.1.1
                // Hostname/domain should appear after 250

                const response = [
                    `${this.local.host} Hello ${this.get_remote('host')}, ${cfg.message.helo}`,
                    "PIPELINING",
                    "8BITMIME",
                ];

                if (cfg.main.smtputf8) response.push("SMTPUTF8");

                response.push(`SIZE ${cfg.max.bytes}`);

                this.capabilities = response;

                plugins.run_hooks('capabilities', this);
                this.esmtp = true;
            }
        }
    }
    capabilities_respond (retval, msg) {
        this.respond(250, this.capabilities);
    }
    quit_respond (retval, msg) {
        this.respond(221, msg || `${this.local.host} ${cfg.message.close}`, () => {
            this.disconnect();
        });
    }
    vrfy_respond (retval, msg) {
        switch (retval) {
            case constants.deny:
                this.respond(550, msg || "Access Denied", () => {
                    this.reset_transaction();
                });
                break;
            case constants.denydisconnect:
                this.respond(550, msg || "Access Denied", () => {
                    this.disconnect();
                });
                break;
            case constants.denysoft:
                this.respond(450, msg || "Lookup Failed", () => {
                    this.reset_transaction();
                });
                break;
            case constants.denysoftdisconnect:
                this.respond(450, msg || "Lookup Failed", () => {
                    this.disconnect();
                });
                break;
            case constants.ok:
                this.respond(250, msg || "User OK");
                break;
            default:
                this.respond(252, "Just try sending a mail and we'll see how it turns out...");
        }
    }
    noop_respond (retval, msg) {
        switch (retval) {
            case constants.deny:
                this.respond(500, msg || "Stop wasting my time");
                break;
            case constants.denydisconnect:
                this.respond(500, msg || "Stop wasting my time", () => {
                    this.disconnect();
                });
                break;
            default:
                this.respond(250, "OK");
        }
    }
    rset_respond (retval, msg) {
        this.respond(250, "OK", () => {
            this.reset_transaction();
        })
    }
    mail_respond (retval, msg) {
        if (!this.transaction) {
            this.logerror("mail_respond found no transaction!");
            return;
        }
        const sender = this.transaction.mail_from;
        const dmsg   = `sender ${sender.format()}`;
        this.lognotice(
            dmsg,
            {
                'code': constants.translate(retval),
                'msg': (msg || ''),
            }
        );

        const store_results = (action) => {
            let addr = sender.format();
            if (addr.length > 2) {  // all but null sender
                addr = addr.substr(1, addr.length -2); // trim off < >
            }
            this.transaction.results.add({name: 'mail_from'}, {
                action,
                code: constants.translate(retval),
                address: addr,
            });
        }

        switch (retval) {
            case constants.deny:
                this.respond(550, msg || `${dmsg} denied`, () => {
                    store_results('reject');
                    this.reset_transaction();
                });
                break;
            case constants.denydisconnect:
                this.respond(550, msg ||  `${dmsg} denied`, () => {
                    store_results('reject');
                    this.disconnect();
                });
                break;
            case constants.denysoft:
                this.respond(450, msg || `${dmsg} denied`, () => {
                    store_results('tempfail');
                    this.reset_transaction();
                });
                break;
            case constants.denysoftdisconnect:
                this.respond(450, msg || `${dmsg} denied`, () => {
                    store_results('tempfail');
                    this.disconnect();
                });
                break;
            default:
                store_results('accept');
                this.respond(250, msg || `${dmsg} OK`);
        }
    }
    rcpt_incr (rcpt, action, msg, retval) {
        this.transaction.rcpt_count[action]++;
        this.rcpt_count[action]++;

        const addr = rcpt.format();
        const recipient = {
            address: addr.substr(1, addr.length -2),
            action
        };

        if (msg && action !== 'accept') {
            if (typeof msg === 'object' && msg.constructor.name === 'DSN') {
                recipient.msg  = msg.reply;
                recipient.code = msg.code;
            }
            else {
                recipient.msg  = msg;
                recipient.code = constants.translate(retval);
            }
        }

        this.transaction.results.push({name: 'rcpt_to'}, { recipient });
    }
    rcpt_ok_respond (retval, msg) {
        if (!this.transaction) {
            this.results.add(this, {err: 'rcpt_ok_respond found no transaction'});
            return;
        }
        if (!msg) msg = this.last_rcpt_msg;
        const rcpt = this.transaction.rcpt_to[this.transaction.rcpt_to.length - 1];
        const dmsg = `recipient ${rcpt.format()}`;
        // Log OK instead of CONT as this hook only runs if hook_rcpt returns OK
        this.lognotice(
            dmsg,
            {
                'code': constants.translate((retval === constants.cont ? constants.ok : retval)),
                'msg': (msg || ''),
                'sender': this.transaction.mail_from.address(),
            }
        );
        switch (retval) {
            case constants.deny:
                this.respond(550, msg || `${dmsg} denied`, () => {
                    this.rcpt_incr(rcpt, 'reject', msg, retval);
                    this.transaction.rcpt_to.pop();
                });
                break;
            case constants.denydisconnect:
                this.respond(550, msg || `${dmsg} denied`, () => {
                    this.rcpt_incr(rcpt, 'reject', msg, retval);
                    this.disconnect();
                });
                break;
            case constants.denysoft:
                this.respond(450, msg || `${dmsg} denied`, () => {
                    this.rcpt_incr(rcpt, 'tempfail', msg, retval);
                    this.transaction.rcpt_to.pop();
                });
                break;
            case constants.denysoftdisconnect:
                this.respond(450, msg || `${dmsg} denied`, () => {
                    this.rcpt_incr(rcpt, 'tempfail', msg, retval);
                    this.disconnect();
                });
                break;
            default:
                this.respond(250, msg || `${dmsg} OK`, () => {
                    this.rcpt_incr(rcpt, 'accept', msg, retval);
                });
        }
    }
    rcpt_respond (retval, msg) {
        if (retval === constants.cont && this.relaying) {
            retval = constants.ok;
        }

        if (!this.transaction) {
            this.results.add(this, {err: 'rcpt_respond found no transaction'});
            return;
        }
        const rcpt = this.transaction.rcpt_to[this.transaction.rcpt_to.length - 1];
        const dmsg = `recipient ${rcpt.format()}`;
        if (retval !== constants.ok) {
            this.lognotice(
                dmsg,
                {
                    'code': constants.translate((retval === constants.cont ? constants.ok : retval)),
                    'msg': (msg || ''),
                    'sender': this.transaction.mail_from.address(),
                }
            );
        }
        switch (retval) {
            case constants.deny:
                this.respond(550, msg || `${dmsg} denied`, () => {
                    this.rcpt_incr(rcpt, 'reject', msg, retval);
                    this.transaction.rcpt_to.pop();
                });
                break;
            case constants.denydisconnect:
                this.respond(550, msg || `${dmsg} denied`, () => {
                    this.rcpt_incr(rcpt, 'reject', msg, retval);
                    this.disconnect();
                });
                break;
            case constants.denysoft:
                this.respond(450, msg || `${dmsg} denied`, () => {
                    this.rcpt_incr(rcpt, 'tempfail', msg, retval);
                    this.transaction.rcpt_to.pop();
                });
                break;
            case constants.denysoftdisconnect:
                this.respond(450, msg || `${dmsg} denied`, () => {
                    this.rcpt_incr(rcpt, 'tempfail', msg, retval);
                    this.disconnect();
                });
                break;
            case constants.ok:
                // Store any msg for rcpt_ok
                this.last_rcpt_msg = msg;
                plugins.run_hooks('rcpt_ok', this, rcpt);
                break;
            default: {
                if (retval !== constants.cont) {
                    this.logalert("No plugin determined if relaying was allowed");
                }
                const rej_msg = `I cannot deliver mail for ${rcpt.format()}`;
                this.respond(550, rej_msg, () => {
                    this.rcpt_incr(rcpt, 'reject', rej_msg, retval);
                    this.transaction.rcpt_to.pop();
                });
            }
        }
    }
    /////////////////////////////////////////////////////////////////////////////
    // HAProxy support

    cmd_proxy (line) {

        if (!this.proxy.allowed) {
            this.respond(421, `PROXY not allowed from ${this.remote.ip}`);
            return this.disconnect();
        }

        const match = /(TCP4|TCP6|UNKNOWN) (\S+) (\S+) (\d+) (\d+)$/.exec(line);
        if (!match) {
            this.respond(421, 'Invalid PROXY format');
            return this.disconnect();
        }
        const proto = match[1];
        const src_ip = match[2];
        const dst_ip = match[3];
        const src_port = match[4];
        const dst_port = match[5];

        // Validate source/destination IP
        /*eslint no-fallthrough: 0 */
        switch (proto) {
            case 'TCP4':
                if (ipaddr.IPv4.isValid(src_ip) && ipaddr.IPv4.isValid(dst_ip)) {
                    break;
                }
            case 'TCP6':
                if (ipaddr.IPv6.isValid(src_ip) && ipaddr.IPv6.isValid(dst_ip)) {
                    break;
                }
            // case 'UNKNOWN':
            default:
                this.respond(421, 'Invalid PROXY format');
                return this.disconnect();
        }

        // Apply changes
        this.loginfo(
            'HAProxy',
            {
                proto,
                src_ip: `${src_ip}:${src_port}`,
                dst_ip: `${dst_ip}:${dst_port}`,
            }
        );

        this.notes.proxy = {
            type: 'haproxy',
            proto,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            proxy_ip: this.remote.ip
        };

        this.reset_transaction(() => {
            this.set('proxy.ip', this.remote.ip);
            this.set('proxy.type', 'haproxy');
            this.relaying = false;
            this.set('local.ip', dst_ip);
            this.set('local.port', parseInt(dst_port, 10));
            this.set('remote.ip', src_ip);
            this.set('remote.port', parseInt(src_port, 10));
            this.set('remote.host', null);
            this.set('hello.host', null);
            plugins.run_hooks('connect_init', this);
        });
    }
    /////////////////////////////////////////////////////////////////////////////
    // SMTP Commands

    cmd_internalcmd (line) {
        if (!this.remote.is_local) {
            return this.respond(501, "INTERNALCMD not allowed remotely");
        }
        const results = (String(line)).split(/ +/);
        if (/key:/.test(results[0])) {
            const internal_key = config.get('internalcmd_key');
            if (results[0] != `key:${internal_key}`) {
                return this.respond(501, "Invalid internalcmd_key - check config");
            }
            results.shift();
        }
        else if (config.get('internalcmd_key')) {
            return this.respond(501, "Missing internalcmd_key - check config");
        }

        // Now send the internal command to the master process
        const command = results.shift();
        if (!command) {
            return this.respond(501, "No command given");
        }

        require('./server').sendToMaster(command, results);
        return this.respond(250, "Command sent for execution. Check Haraka logs for results.");
    }
    cmd_helo (line) {
        const results = (String(line)).split(/ +/);
        const host = results[0];
        if (!host) {
            return this.respond(501, "HELO requires domain/address - see RFC-2821 4.1.1.1");
        }

        this.reset_transaction(() => {
            this.set('hello', 'verb', 'HELO');
            this.set('hello', 'host', host);
            this.results.add({ name: 'helo' }, this.hello);
            plugins.run_hooks('helo', this, host);
        });
    }
    cmd_ehlo (line) {
        const results = (String(line)).split(/ +/);
        const host = results[0];
        if (!host) {
            return this.respond(501, "EHLO requires domain/address - see RFC-2821 4.1.1.1");
        }

        this.reset_transaction(() => {
            this.set('hello', 'verb', 'EHLO');
            this.set('hello', 'host', host);
            this.results.add({ name: 'helo' }, this.hello);
            plugins.run_hooks('ehlo', this, host);
        });
    }
    cmd_quit (args) {
        // RFC 5321 Section 4.3.2
        // QUIT does not accept arguments
        if (args) {
            return this.respond(501, "Syntax error");
        }
        plugins.run_hooks('quit', this);
    }
    cmd_rset (args) {
        // RFC 5321 Section 4.3.2
        // RSET does not accept arguments
        if (args) {
            return this.respond(501, "Syntax error");
        }
        plugins.run_hooks('rset', this);
    }
    cmd_vrfy (line) {
        // only supported via plugins
        plugins.run_hooks('vrfy', this);
    }
    cmd_noop () {
        plugins.run_hooks('noop', this);
    }
    cmd_help () {
        this.respond(250, "Not implemented");
    }
    cmd_mail (line) {
        if (!this.hello.host) {
            this.errors++;
            return this.respond(503, 'Use EHLO/HELO before MAIL');
        }
        // Require authentication on ports 587 & 465
        if (!this.relaying && [587,465].includes(this.local.port)) {
            this.errors++;
            return this.respond(550, 'Authentication required');
        }

        let results;
        try {
            results = rfc1869.parse('mail', line, (!this.relaying && cfg.main.strict_rfc1869));
        }
        catch (err) {
            this.errors++;
            if (err.stack) {
                this.lognotice(err.stack.split(/\n/)[0]);
            }
            else {
                this.logerror(err);
            }
            // Explicitly handle out-of-disk space errors
            if (err.code === 'ENOSPC') {
                return this.respond(452, 'Internal Server Error');
            }
            else {
                return this.respond(501, ['Command parsing failed', err]);
            }
        }

        let from;
        try {
            from = new Address(results.shift());
        }
        catch (err) {
            return this.respond(501, `Invalid MAIL FROM address`);
        }

        // Get rest of key=value pairs
        const params = {};
        results.forEach(param => {
            const kv = param.match(/^([^=]+)(?:=(.+))?$/);
            if (kv)
                params[kv[1].toUpperCase()] = kv[2] || null;
        });

        // Parameters are only valid if EHLO was sent
        if (!this.esmtp && Object.keys(params).length > 0) {
            return this.respond(555, 'Invalid command parameters');
        }

        // Handle SIZE extension
        if (params?.SIZE && params.SIZE > 0) {
            if (cfg.max.bytes > 0 && params.SIZE > cfg.max.bytes) {
                return this.respond(550, 'Message too big!');
            }
        }

        this.init_transaction(() => {
            this.transaction.mail_from = from;
            if (this.hello.verb == 'HELO') {
                this.transaction.encoding = 'binary';
                this.encoding = 'binary';
            }
            plugins.run_hooks('mail', this, [from, params]);
        });
    }
    cmd_rcpt (line) {
        if (!this.transaction || !this.transaction.mail_from) {
            this.errors++;
            return this.respond(503, "Use MAIL before RCPT");
        }

        let results;
        try {
            results = rfc1869.parse('rcpt', line, cfg.main.strict_rfc1869 && !this.relaying);
        }
        catch (err) {
            this.errors++;
            if (err.stack) {
                this.lognotice(err.stack.split(/\n/)[0]);
            }
            else {
                this.logerror(err);
            }
            // Explicitly handle out-of-disk space errors
            if (err.code === 'ENOSPC') {
                return this.respond(452, 'Internal Server Error');
            }
            else {
                return this.respond(501, ["Command parsing failed", err]);
            }
        }

        let recip;
        try {
            recip = new Address(results.shift());
        }
        catch (err) {
            return this.respond(501, `Invalid RCPT TO address`);
        }

        // Get rest of key=value pairs
        const params = {};
        results.forEach((param) => {
            const kv = param.match(/^([^=]+)(?:=(.+))?$/);
            if (kv)
                params[kv[1].toUpperCase()] = kv[2] || null;
        });

        // Parameters are only valid if EHLO was sent
        if (!this.esmtp && Object.keys(params).length > 0) {
            return this.respond(555, 'Invalid command parameters');
        }

        this.transaction.rcpt_to.push(recip);
        plugins.run_hooks('rcpt', this, [recip, params]);
    }
    received_line () {
        let smtp = this.hello.verb === 'EHLO' ? 'ESMTP' : 'SMTP';
        // Implement RFC3848
        if (this.tls.enabled) smtp += 'S';
        if (this.authheader) smtp += 'A';

        let sslheader;

        if (this.get('tls.cipher.version')) {
            // standardName appeared in Node.js v12.16 and v13.4
            // RFC 8314
            sslheader = `tls ${this.tls.cipher.standardName || this.tls.cipher.name}`;
        }

        let received_header = `from ${this.hello.host} (${this.get_remote('info')})\r
\tby ${this.local.host} (${this.local.info}) with ${smtp} id ${this.transaction.uuid}\r
\tenvelope-from ${this.transaction.mail_from.format()}`;

        if (sslheader)       received_header += `\r\n\t${sslheader.replace(/\r?\n\t?$/,'')}`

        // Does not follow RFC 5321 section 4.4 grammar
        if (this.authheader) received_header += ` ${this.authheader.replace(/\r?\n\t?$/, '')}`

        received_header += `;\r\n\t${utils.date_to_str(new Date())}`

        return received_header;
    }
    auth_results (message) {
        // https://datatracker.ietf.org/doc/rfc7001/
        const has_tran = !!((this.transaction?.notes));

        // initialize connection note
        if (!this.notes.authentication_results) {
            this.notes.authentication_results = [];
        }

        // initialize transaction note, if possible
        if (has_tran === true && !this.transaction.notes.authentication_results) {
            this.transaction.notes.authentication_results = [];
        }

        // if message, store it in the appropriate note
        if (message) {
            if (has_tran === true) {
                this.transaction.notes.authentication_results.push(message);
            }
            else {
                this.notes.authentication_results.push(message);
            }
        }

        // assemble the new header
        let header = [ this.local.host ];
        header = header.concat(this.notes.authentication_results);
        if (has_tran === true) {
            header = header.concat(this.transaction.notes.authentication_results);
        }
        if (header.length === 1) return '';  // no results
        return header.join(";\r\n\t");
    }
    auth_results_clean () {
        // move any existing Auth-Res headers to Original-Auth-Res headers
        // http://tools.ietf.org/html/draft-kucherawy-original-authres-00.html
        const ars = this.transaction.header.get_all('Authentication-Results');
        if (ars.length === 0) return;

        for (const element of ars) {
            this.transaction.add_header('Original-Authentication-Results', element);
        }
        this.transaction.remove_header('Authentication-Results');
        this.logdebug("Authentication-Results moved to Original-Authentication-Results");
    }
    cmd_data (args) {
        // RFC 5321 Section 4.3.2
        // DATA does not accept arguments
        if (args) {
            this.errors++;
            return this.respond(501, "Syntax error");
        }
        if (!this.transaction) {
            this.errors++;
            return this.respond(503, "MAIL required first");
        }
        if (!this.transaction.rcpt_to.length) {
            if (this.pipelining) {
                return this.respond(554, "No valid recipients");
            }
            this.errors++;
            return this.respond(503, "RCPT required first");
        }

        if (cfg.headers.add_received) {
            this.accumulate_data(`Received: ${this.received_line()}\r\n`);
        }
        plugins.run_hooks('data', this);
    }
    data_respond (retval, msg) {
        let cont = 0;
        switch (retval) {
            case constants.deny:
                this.respond(554, msg || "Message denied", () => {
                    this.reset_transaction();
                });
                break;
            case constants.denydisconnect:
                this.respond(554, msg || "Message denied", () => {
                    this.disconnect();
                });
                break;
            case constants.denysoft:
                this.respond(451, msg || "Message denied", () => {
                    this.reset_transaction();
                });
                break;
            case constants.denysoftdisconnect:
                this.respond(451, msg || "Message denied", () => {
                    this.disconnect();
                });
                break;
            default:
                cont = 1;
        }
        if (!cont) return;

        // We already checked for MAIL/RCPT in cmd_data
        this.respond(354, "go ahead, make my day", () => {
            // OK... now we get the data
            this.state = states.DATA;
            this.transaction.data_bytes = 0;
        });
    }
    accumulate_data (line) {

        this.transaction.data_bytes += line.length;

        // Look for .\r\n
        if (line.length === 3 &&
            line[0] === 0x2e &&
            line[1] === 0x0d &&
            line[2] === 0x0a) {
            this.data_done();
            return;
        }

        // Look for .\n
        if (line.length === 2 &&
            line[0] === 0x2e &&
            line[1] === 0x0a) {
            this.lognotice('Client sent bare line-feed - .\\n rather than .\\r\\n');
            this.respond(451, "Bare line-feed; see http://haraka.github.io/barelf/", () => {
                this.reset_transaction();
            });
            return;
        }

        // Stop accumulating data as we're going to reject at dot.
        if (cfg.max.bytes && this.transaction.data_bytes > cfg.max.bytes) {
            return;
        }

        if (this.transaction.mime_part_count >= cfg.max.mime_parts) {
            this.logcrit("Possible DoS attempt - too many MIME parts");
            this.respond(554, "Transaction failed due to too many MIME parts", () => {
                this.disconnect();
            });
            return;
        }

        this.transaction.add_data(line);
    }
    data_done () {
        this.pause();
        this.totalbytes += this.transaction.data_bytes;

        // Check message size limit
        if (cfg.max.bytes && this.transaction.data_bytes > cfg.max.bytes) {
            this.lognotice(`Incoming message exceeded max size of ${cfg.max.bytes}`);
            return plugins.run_hooks('max_data_exceeded', this);
        }

        // Check max received headers count
        if (this.transaction.header.get_all('received').length > cfg.headers.max_received) {
            this.logerror("Incoming message had too many Received headers");
            this.respond(550, "Too many received headers - possible mail loop", () => {
                this.reset_transaction();
            });
            return;
        }

        // Warn if we hit the maximum parsed header lines limit
        if (this.transaction.header_lines.length >= cfg.headers.max_lines) {
            this.logwarn(`Incoming message reached maximum parsing limit of ${cfg.headers.max_lines} header lines`);
        }

        if (cfg.headers.clean_auth_results) {
            this.auth_results_clean();   // rename old A-R headers
        }
        const ar_field = this.auth_results();  // assemble new one
        if (ar_field) {
            this.transaction.add_header('Authentication-Results', ar_field);
        }

        this.transaction.end_data(() => {
            // As this will be called asynchronously,
            // make sure we still have a transaction.
            if (!this.transaction) return;
            // Record the start time of this hook as we can't take too long
            // as the client will typically hang up after 2 to 3 minutes
            // despite the RFC mandating that 10 minutes should be allowed.
            this.transaction.data_post_start = Date.now();
            plugins.run_hooks('data_post', this);
        });
    }
    data_post_respond (retval, msg) {
        if (!this.transaction) return;
        this.transaction.data_post_delay = (Date.now() - this.transaction.data_post_start)/1000;
        const mid = this.transaction.header.get('Message-ID') || '';
        this.lognotice(
            'message',
            {
                'mid': mid.replace(/\r?\n/,''),
                'size': this.transaction.data_bytes,
                'rcpts': `${this.transaction.rcpt_count.accept}/${this.transaction.rcpt_count.tempfail}/${this.transaction.rcpt_count.reject}`,
                'delay': this.transaction.data_post_delay,
                'code':  constants.translate(retval),
                'msg': (msg || ''),
            }
        );
        const ar_field = this.auth_results();  // assemble A-R header
        if (ar_field) {
            this.transaction.remove_header('Authentication-Results');
            this.transaction.add_leading_header('Authentication-Results', ar_field);
        }
        switch (retval) {
            case constants.deny:
                this.respond(550, msg || "Message denied", () => {
                    this.msg_count.reject++;
                    this.transaction.msg_status = 'rejected';
                    this.reset_transaction(() => this.resume());
                });
                break;
            case constants.denydisconnect:
                this.respond(550, msg || "Message denied",() => {
                    this.msg_count.reject++;
                    this.transaction.msg_status = 'rejected';
                    this.disconnect();
                });
                break;
            case constants.denysoft:
                this.respond(450, msg || "Message denied temporarily", () =>  {
                    this.msg_count.tempfail++;
                    this.transaction.msg_status = 'deferred';
                    this.reset_transaction(() => this.resume());
                });
                break;
            case constants.denysoftdisconnect:
                this.respond(450, msg || "Message denied temporarily",() => {
                    this.msg_count.tempfail++;
                    this.transaction.msg_status = 'deferred';
                    this.disconnect();
                });
                break;
            default:
                if (this.relaying) {
                    plugins.run_hooks("queue_outbound", this);
                }
                else {
                    plugins.run_hooks("queue", this);
                }
        }
    }
    max_data_exceeded_respond (retval, msg) {
        // TODO: Maybe figure out what to do with other return codes
        this.respond(retval === constants.denysoft ? 450 : 550, "Message too big!", () => {
            this.reset_transaction();
        });
    }
    queue_msg (retval, msg) {
        if (msg) {
            if (typeof msg === 'object' && msg.constructor.name === 'DSN') {
                return msg.reply
            }
            return msg;
        }

        switch (retval) {
            case constants.ok:
                return 'Message Queued';
            case constants.deny:
            case constants.denydisconnect:
                return 'Message denied';
            case constants.denysoft:
            case constants.denysoftdisconnect:
                return 'Message denied temporarily';
            default:
                return '';
        }
    }
    store_queue_result (retval, msg) {
        const res_as = {name: 'queue'};
        switch (retval) {
            case constants.ok:
                this.transaction.results.add(res_as, { pass: msg });
                break;
            case constants.deny:
            case constants.denydisconnect:
            case constants.denysoft:
            case constants.denysoftdisconnect:
                this.transaction.results.add(res_as, { fail: msg });
                break;
            case constants.cont:
                break;
            default:
                this.transaction.results.add(res_as, { msg });
                break;
        }
    }
    queue_outbound_respond (retval, msg) {
        if (this.remote.closed) return;
        msg = this.queue_msg(retval, msg) || 'Message Queued';
        this.store_queue_result(retval, msg);
        msg = `${msg} (${this.transaction.uuid})`;
        if (retval !== constants.ok) {
            this.lognotice(
                'queue',
                {
                    code: constants.translate(retval),
                    msg
                }
            );
        }
        switch (retval) {
            case constants.ok:
                plugins.run_hooks('queue_ok', this, msg);
                break;
            case constants.deny:
                this.respond(550, msg, () => {
                    this.msg_count.reject++;
                    this.transaction.msg_status = 'rejected';
                    this.reset_transaction(() => this.resume());
                });
                break;
            case constants.denydisconnect:
                this.respond(550, msg, () => {
                    this.msg_count.reject++;
                    this.transaction.msg_status = 'rejected';
                    this.disconnect();
                });
                break;
            case constants.denysoft:
                this.respond(450, msg, () => {
                    this.msg_count.tempfail++;
                    this.transaction.msg_status = 'deferred';
                    this.reset_transaction(() => this.resume());
                });
                break;
            case constants.denysoftdisconnect:
                this.respond(450, msg, () => {
                    this.msg_count.tempfail++;
                    this.transaction.msg_status = 'deferred';
                    this.disconnect();
                });
                break;
            default:
                outbound.send_trans_email(this.transaction, (retval2, msg2) => {
                    if (!msg2) msg2 = this.queue_msg(retval2, msg);
                    switch (retval2) {
                        case constants.ok:
                            if (!msg2) msg2 = this.queue_msg(retval2, msg2);
                            plugins.run_hooks('queue_ok', this, msg2);
                            break;
                        case constants.deny:
                            if (!msg2) msg2 = this.queue_msg(retval2, msg2);
                            this.respond(550, msg2, () => {
                                this.msg_count.reject++;
                                this.transaction.msg_status = 'rejected';
                                this.reset_transaction(() => {
                                    this.resume();
                                });
                            });
                            break;
                        default:
                            this.logerror(`Unrecognized response from outbound layer: ${retval2} : ${msg2}`);
                            this.respond(550, msg2 || "Internal Server Error", () => {
                                this.msg_count.reject++;
                                this.transaction.msg_status = 'rejected';
                                this.reset_transaction(() => {
                                    this.resume();
                                });
                            });
                    }
                });
        }
    }
    queue_respond (retval, msg) {
        msg = this.queue_msg(retval, msg);
        this.store_queue_result(retval, msg);
        msg = `${msg} (${this.transaction.uuid})`;

        if (retval !== constants.ok) {
            this.lognotice(
                'queue',
                {
                    code: constants.translate(retval),
                    msg
                }
            );
        }
        switch (retval) {
            case constants.ok:
                plugins.run_hooks('queue_ok', this, msg);
                break;
            case constants.deny:
                this.respond(550, msg, () => {
                    this.msg_count.reject++;
                    this.transaction.msg_status = 'rejected';
                    this.reset_transaction(() =>  this.resume());
                });
                break;
            case constants.denydisconnect:
                this.respond(550, msg, () => {
                    this.msg_count.reject++;
                    this.transaction.msg_status = 'rejected';
                    this.disconnect();
                });
                break;
            case constants.denysoft:
                this.respond(450, msg, () => {
                    this.msg_count.tempfail++;
                    this.transaction.msg_status = 'deferred';
                    this.reset_transaction(() => this.resume());
                });
                break;
            case constants.denysoftdisconnect:
                this.respond(450, msg, () => {
                    this.msg_count.tempfail++;
                    this.transaction.msg_status = 'deferred';
                    this.disconnect();
                });
                break;
            default:
                if (!msg) msg = 'Queuing declined or disabled, try later';
                this.respond(451, msg, () => {
                    this.msg_count.tempfail++;
                    this.transaction.msg_status = 'deferred';
                    this.reset_transaction(() => this.resume());
                });
                break;
        }
    }
    queue_ok_respond (retval, msg, params) {
        // This hook is common to both hook_queue and hook_queue_outbound
        // retval and msg are ignored in this hook so we always log OK
        this.lognotice(
            'queue',
            {
                code: 'OK',
                msg: (params || '')
            }
        );

        this.respond(250, params, () => {
            this.msg_count.accept++;
            if (this.transaction) this.transaction.msg_status = 'accepted';
            this.reset_transaction(() => this.resume());
        });
    }
}

exports.Connection = Connection;

exports.createConnection = (client, server, cfg) => {
    return new Connection(client, server, cfg);
}

logger.add_log_methods(Connection)
