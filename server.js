'use strict';
// smtp network server

const cluster     = require('node:cluster');
const fs          = require('node:fs');
const os          = require('node:os');
const path        = require('node:path');
const tls         = require('node:tls');

const daemon      = require('daemon');
const constants   = require('haraka-constants');

const tls_socket  = require('./tls_socket');
const conn        = require('./connection');
const outbound    = require('./outbound');
const endpoint    = require('./endpoint');

const Server      = exports;
Server.logger     = require('./logger');
Server.config     = require('haraka-config');
Server.plugins    = require('./plugins');
Server.notes      = {};

const { logger }  = Server;

// Need these here so we can run hooks
logger.add_log_methods(Server, 'server');

Server.listeners = [];

/**
 *  加载 smtp.ini配置文件
 *  处理配置默认值
 */
Server.load_smtp_ini = () => {
    Server.cfg = Server.config.get('smtp.ini', {
        booleans: [
            '-main.daemonize',
            '-main.graceful_shutdown',
        ],
    }, () => {
        Server.load_smtp_ini();
    });

    if (Server.cfg.main.nodes === undefined) {
        Server.logwarn(`smtp.ini.nodes unset, using 1, see https://github.com/haraka/Haraka/wiki/Performance-Tuning`)
    }

    const defaults = {
        inactivity_timeout: 300,
        daemon_log_file: '/var/log/haraka.log',
        daemon_pid_file: '/var/run/haraka.pid',
        force_shutdown_timeout: 30,
        smtps_port: 465,
        nodes: 1,
    };

    for (const key in defaults) {
        if (Server.cfg.main[key] !== undefined) continue;
        Server.cfg.main[key] = defaults[key];
    }
}

/**
 *  加载http.ini 配置文件
 */
Server.load_http_ini = () => {
    Server.http = {};
    Server.http.cfg = Server.config.get('http.ini', () => {
        Server.load_http_ini();
    }).main;
}

Server.load_smtp_ini();
Server.load_http_ini();

/**
 * 将进程转为守护进程
 * 处理日志文件和PID文件
 * @returns
 */
Server.daemonize = function () {
    const c = this.cfg.main;
    // 获取主配置，其中包含是否守护化、日志文件路径和PID文件路径等设置

    if (!c.daemonize) return;
    // 如果配置中没有启用守护化（daemonize=false），则直接返回，不执行守护化操作

    if (!process.env.__daemon) {
        // 检查环境变量 __daemon。这个变量通常由 daemon 模块设置，
        // 用于标识当前进程是否已经是守护进程的子进程。
        // 如果没有设置，说明当前是初始进程，需要进行守护化操作。

        // Remove process.on('exit') listeners otherwise
        // we get a spurious 'Exiting' log entry.
        // 移除所有 'exit' 事件的监听器，以避免在守护化过程中产生不必要的“Exiting”日志条目
        process.removeAllListeners('exit');
        Server.lognotice('Daemonizing...');
        // 记录日志，表示正在进行守护化
    }

    Server.lognotice(`Open daemon log file: ${c.daemon_log_file}...`);
    const log_fd = fs.openSync(c.daemon_log_file, 'a');
    // 打开或创建守护进程的日志文件（通常是 /var/log/haraka.log），以追加模式写入

    Server.lognotice('call daemon module...');
    daemon({ cwd: process.cwd(), stdout: log_fd });
    // 调用 'daemon' 模块，执行实际的守护化操作。
    // 这会使当前进程 fork 出一个子进程，父进程退出，子进程成为会话组长，脱离控制终端。
    // `cwd` 设置工作目录，`stdout` 将标准输出重定向到指定的日志文件描述符

    // We are the daemon from here on...
    // 从这里开始，代码在守护进程的上下文中执行

    Server.lognotice('Import npid module...');
    const npid = require('npid');
    // 导入 'npid' 模块，用于创建和管理 PID 文件

    try {

        // 检查PID文件是否存在
        if(fs.existsSync(c.daemon_pid_file)){
            //读取PID文件
            const pid= parseInt(fs.readFileSync(c.daemon_pid_file,'utf8'));
            //检查该PID是否正在运行
            try{
                // 发送0信号，如果进程存在，不会杀死它，但会检查是否存在
                process.kill(pid,0);
                // 如果成功，说明进程正在运行
                Server.logerror(`PID file ${c.daemon_pid_file} alrady exists and process ${pid} is running. Exiting.`);
                logger.dump_and_exit(1);
            }catch(err){
                // 如果错误是ESRCH，表示进程不存在
                if ( err.code ==='ESRCH'){
                    Server.lognotice(`Removing stale PID file ${c.daemon_pid_file} (process ${pid} not found).`);
                    fs.unlinkSync(c.daemon_pid_file);
                }else{
                    // 其他错误，比如权限问题，记录错误信息
                    Server.logerror(`Error checking PID ${pid}: ${err.message}`);
                    logger.dump_and_exit(1); 
                }
            }

        }

        Server.lognotice('Create daemon_pid_file...');
        npid.create(c.daemon_pid_file).removeOnExit();
        // 创建 PID 文件（通常是 /var/run/haraka.pid），其中包含守护进程的进程ID。
        // `removeOnExit()` 确保当进程正常退出时，PID 文件会被自动删除。

        Server.lognotice('Exit npid...')
    }
    catch (err) {
        Server.logerror('catch err: '+err.message);
        // 如果创建 PID 文件失败，记录错误信息
        logger.dump_and_exit(1);
        // 记录所有缓冲的日志并以错误码 1 退出进程
    }
}

/**
 * 刷新邮件队列
 * @param {*} domain 
 * @returns 
 */
Server.flushQueue = domain => {
    if (!Server.cluster) {
        outbound.flush_queue(domain);
        return;
    }

    for (const id in cluster.workers) {
        cluster.workers[id].send({event: 'outbound.flush_queue', domain});
    }
}

let graceful_in_progress = false;

Server.gracefulRestart = () => {
    Server._graceful();
}

Server.stopListeners = () => {
    Server.loginfo('Shutting down listeners');
    for (const l of Server.listeners) {
        l.close();
    }
    Server.listeners = [];
}

/**
 * 执行服务器关闭操作
 * @returns 
 */
Server.performShutdown = () => {
    if (Server.cfg.main.graceful_shutdown) {
        return Server.gracefulShutdown();
    }
    Server.loginfo("Shutting down.");
    process.exit(0);
}

/**
 * 优雅地关闭服务器
 */
Server.gracefulShutdown = () => {
    Server.stopListeners();
    Server._graceful(() => {
        // log();
        Server.loginfo("Failed to shutdown naturally. Exiting.");
        process.exit(0);
    });
}

Server._graceful = async (shutdown) => {
    if (!Server.cluster && shutdown) {
        for (const module of ['outbound', 'cfreader', 'plugins']) {
            process.emit('message', {event: `${module}.shutdown`});
        }
        const t = setTimeout(shutdown, Server.cfg.main.force_shutdown_timeout * 1000);
        return t.unref();
    }

    if (graceful_in_progress) {
        Server.lognotice("Restart currently in progress - ignoring request");
        return;
    }

    graceful_in_progress = true;
    // TODO: Make these configurable
    const disconnect_timeout = 30;
    const exit_timeout = 30;
    cluster.removeAllListeners('exit');

    // we reload using eachLimit where limit = num_workers - 1
    // this kills all-but-one workers in parallel, leaving one running
    // for new connections, and then restarts that one last worker.

    const worker_ids = Object.keys(cluster.workers);
    let limit = worker_ids.length - 1;
    if (limit < 2) limit = 1;

    const todo = []

    for (const id of Object.keys(cluster.workers)) {
        todo.push((id) => {
            return new Promise((resolve) => {
                Server.lognotice(`Killing worker: ${id}`);
                const worker = cluster.workers[id];
                for (const module of ['outbound', 'cfreader', 'plugins']) {
                    worker.send({event: `${module  }.shutdown`});
                }
                worker.disconnect();
                let disconnect_received = false;
                const disconnect_timer = setTimeout(() => {
                    if (!disconnect_received) {
                        Server.logcrit("Disconnect never received by worker. Killing.");
                        worker.kill();
                    }
                }, disconnect_timeout * 1000);

                worker.once('disconnect', () => {
                    clearTimeout(disconnect_timer);
                    disconnect_received = true;
                    Server.lognotice('Disconnect complete');
                    let dead = false;
                    const timer = setTimeout(() => {
                        if (!dead) {
                            Server.logcrit(`Worker ${id} failed to shutdown. Killing.`);
                            worker.kill();
                        }
                    }, exit_timeout * 1000);
                    worker.once('exit', () => {
                        dead = true;
                        clearTimeout(timer);
                        if (shutdown) resolve()
                    })
                })
                if (!shutdown) {
                    const newWorker = cluster.fork();
                    newWorker.once('listening', () => {
                        Server.lognotice('Replacement worker online.');
                        newWorker.on('exit', (code, signal) => {
                            cluster_exit_listener(newWorker, code, signal);
                        });
                        resolve()
                    })
                }
            })
        })
    }

    while (todo.length) {
        // process batches of workers
        await Promise.all(todo.splice(0, limit))
    }

    if (shutdown) {
        Server.loginfo("Workers closed. Shutting down master process subsystems");
        for (const module of ['outbound', 'cfreader', 'plugins']) {
            process.emit('message', {event: `${module}.shutdown`});
        }
        const t2 = setTimeout(shutdown, Server.cfg.main.force_shutdown_timeout * 1000);
        return t2.unref();
    }
    graceful_in_progress = false;
    Server.lognotice(`Reload complete, workers: ${JSON.stringify(Object.keys(cluster.workers))}`);
}

/**
 * 向主进程发送消息
 * @param {*} command 
 * @param {*} params 
 */
Server.sendToMaster = (command, params) => {
    // console.log("Send to master: ", command);
    if (Server.cluster) {
        if (Server.cluster.isMaster) {
            Server.receiveAsMaster(command, params);
        }
        else {
            process.send({cmd: command, params});
        }
    }
    else {
        Server.receiveAsMaster(command, params);
    }
}

/**
 * 主进程接收并处理消息
 * @param {*} command 
 * @param {*} params 
 * @returns 
 */
Server.receiveAsMaster = (command, params) => {
    if (!Server[command]) {
        Server.logerror(`Invalid command: ${command}`);
        return;
    }
    Server[command].apply(Server, params);
}

/**
 * 消息处理函数
 * @param {*} worker 
 * @param {*} msg 
 * @param {*} handle 
 */
function messageHandler (worker, msg, handle) {
    // sunset Haraka v3 (Node < 6)
    if (arguments.length === 2) {
        handle = msg;
        msg = worker;
        worker = undefined;
    }
    // console.log("received cmd: ", msg);
    if (msg?.cmd) {
        Server.receiveAsMaster(msg.cmd, msg.params);
    }
}

/**
 * 获取监听地址
 * @param {*} cfg 
 * @param {*} port 
 * @returns 
 */
Server.get_listen_addrs = (cfg, port) => {
    if (!port) port = 25;
    let listeners = [];
    if (cfg?.listen) {
        listeners = cfg.listen.split(/\s*,\s*/);
        if (listeners[0] === '') listeners = [];
        for (let i=0; i < listeners.length; i++) {
            const ep = endpoint(listeners[i], port);
            if (ep instanceof Error) continue
            listeners[i] = ep.toString();
        }
    }
    if (cfg.port) {
        let host = cfg.listen_host;
        if (!host) {
            host = '[::0]';
            Server.default_host = true;
        }
        listeners.unshift(`${host}:${cfg.port}`);
    }
    if (listeners.length) return listeners;

    Server.default_host = true;
    listeners.push(`[::0]:${port}`);

    return listeners;
}

/**
 * 创建服务器
 * 处理集群模式
 * 启动SMTP和HTTP监听器
 * @param {*} params 
 * @returns 
 */
Server.createServer = params => {
    const c = Server.cfg.main;
    for (const key in params) {
        if (typeof params[key] === 'function') continue;
        c[key] = params[key];
    }

    Server.notes = {};
    Server.plugins.server = Server;
    Server.plugins.load_plugins();

    const inactivity_timeout = (c.inactivity_timeout || 300) * 1000;

    if (!cluster || !c.nodes) {
        Server.daemonize(c);
        Server.setup_smtp_listeners(Server.plugins, 'master', inactivity_timeout);
        return;
    }

    // Cluster
    Server.cluster = cluster;

    // Cluster Workers
    if (!cluster.isMaster) {
        Server.setup_smtp_listeners(Server.plugins, 'child', inactivity_timeout);
        return;
    }
    else {
        // console.log("Setting up message handler");
        cluster.on('message', messageHandler);
    }

    // Cluster Master
    // We fork workers in init_master_respond so that plugins
    // can put handlers on cluster events before they are emitted.
    Server.plugins.run_hooks('init_master', Server);
}

Server.load_default_tls_config = done => {
    // this fn exists solely for testing
    if (Server.config.root_path != tls_socket.config.root_path) {
        Server.loginfo(`resetting tls_config.config path to ${Server.config.root_path}`);
        tls_socket.config = tls_socket.config.module_config(path.dirname(Server.config.root_path));
    }
    tls_socket.getSocketOpts('*').then(opts => {
        done(opts);
    })
}

/**
 * 创建 SMTP服务器
 * @param {*} ep 
 * @param {*} inactivity_timeout 
 * @returns 
 */
Server.get_smtp_server = async (ep, inactivity_timeout) => {
    let server;

    function onConnect (client) {
        client.setTimeout(inactivity_timeout);
        const connection = conn.createConnection(client, server, Server.cfg);

        if (!server.has_tls) return;

        const cipher = client.getCipher();
        cipher.version = client.getProtocol(); // replace min with actual

        connection.setTLS({
            cipher,
            verified: client.authorized,
            verifyError: client.authorizationError,
            peerCertificate: client.getPeerCertificate(),
        });
    }

    if (ep.port === parseInt(Server.cfg.main.smtps_port, 10)) {
        Server.loginfo('getting SocketOpts for SMTPS server');
        const opts = await tls_socket.getSocketOpts('*')
        Server.loginfo(`Creating TLS server on ${ep}`);

        opts.rejectUnauthorized = tls_socket.get_rejectUnauthorized(opts.rejectUnauthorized, ep.port, tls_socket.cfg.main.requireAuthorized)

        server = tls.createServer(opts, onConnect);
        tls_socket.addOCSP(server);
        server.has_tls=true;
        server.on('resumeSession', (id, rsDone) => {
            Server.loginfo('client requested TLS resumeSession');
            rsDone(null, null);
        })
        Server.listeners.push(server);
        return server
    }
    else {
        server = tls_socket.createServer(onConnect);
        server.has_tls = false;
        const opts = await tls_socket.getSocketOpts('*')
        Server.listeners.push(server);
        return server
    }
}

/**
 * 配置 SMTP 监听器
 * @param {*} plugins2 
 * @param {*} type 
 * @param {*} inactivity_timeout 
 * @returns 
 */
Server.setup_smtp_listeners = async (plugins2, type, inactivity_timeout) => {

    const errors = []

    for (const listen_address of Server.get_listen_addrs(Server.cfg.main)) {

        const ep = endpoint(listen_address, 25);

        if (ep instanceof Error) {
            Server.logerror(`Invalid "listen" format in smtp.ini: ${listen_address}`)
            continue
        }

        const server = await Server.get_smtp_server(ep, inactivity_timeout)
        if (!server) continue;

        server.notes = Server.notes;
        if (Server.cluster) server.cluster = Server.cluster;

        server
            .on('listening', function () {
                const addr = this.address();
                Server.lognotice(`Listening on ${endpoint(addr)}`);
            })
            .on('close', () => {
                Server.loginfo(`Listener ${ep} stopped`);
            })
            .on('error', e => {
                errors.push(e)
                Server.logerror(`Failed to setup listeners: ${e.message}`);
                if (e.code !== 'EAFNOSUPPORT') {
                    Server.logerror(e)
                    return
                }
                // Fallback from IPv6 to IPv4 if not supported
                // But only if we supplied the default of [::0]:25
                if (/^::0/.test(ep.host) && Server.default_host) {
                    server.listen(ep.port, '0.0.0.0', 0);
                    return;
                }
                // Pass error to callback
                Server.logerror(e)
            })

        await ep.bind(server, {backlog: 0});
    }

    if (errors.length) {
        for (const e of errors) {
            Server.logerror(`Failed to setup listeners: ${e.message}`);
        }
        return logger.dump_and_exit(-1);
    }
    Server.listening();
    plugins2.run_hooks(`init_${type}`, Server);
}


/**
 * 配置 HTTP 监听器
 * @returns 
 */
Server.setup_http_listeners = async () => {
    if (!Server.http?.cfg?.listen) return;

    const listeners = Server.get_listen_addrs(Server.http.cfg, 80);
    if (!listeners.length) return;

    try {
        Server.http.express = require('express');
        Server.loginfo('express loaded at Server.http.express');
    }
    catch (err) {
        Server.logerror('express failed to load. No http server. Install express with: npm install -g express');
        return;
    }

    const app = Server.http.express();
    Server.http.app = app;
    Server.loginfo('express app is at Server.http.app');

    for (const listen_address of listeners) {

        const ep = endpoint(listen_address, 80);
        if (ep instanceof Error) {
            Server.logerror(`Invalid format for listen in http.ini: ${listen_address}`)
            continue
        }

        if (443 == ep.port) {
            const tlsOpts = { ...tls_socket.certsByHost['*'] }
            tlsOpts.requestCert = false; // not appropriate for HTTPS
            Server.http.server = require('https').createServer(tlsOpts, app);
        }
        else {
            Server.http.server = require('http').createServer(app);
        }

        Server.listeners.push(Server.http.server);

        Server.http.server.on('listening', function () {
            Server.lognotice(`Listening on ${endpoint(this.address())}`);
        })

        Server.http.server.on('error', e => {
            Server.logerror(e);
        })

        await ep.bind(Server.http.server, {backlog: 0});
    }

    Server.plugins.run_hooks('init_http', Server);
    app.use(Server.http.express.static(Server.get_http_docroot()));
    app.use(Server.handle404);
}

Server.init_master_respond = (retval, msg) => {
    if (!(retval === constants.ok || retval === constants.cont)) {
        Server.logerror(`init_master returned error${((msg) ? `: ${msg}` : '')}`);
        return logger.dump_and_exit(1);
    }

    const c = Server.cfg.main;
    Server.ready = 1;

    // Load the queue if we're just one process
    if (!(cluster && c.nodes)) {
        outbound.load_queue();
        Server.setup_http_listeners();
        return;
    }

    // Running under cluster, fork children here, so that
    // cluster events can be registered in init_master hooks.
    outbound.scan_queue_pids((err, pids) => {
        if (err) {
            Server.logcrit("Scanning queue failed. Shutting down.");
            return logger.dump_and_exit(1);
        }
        Server.daemonize();
        // Fork workers
        const workers = (c.nodes === 'cpus') ? os.cpus().length : c.nodes;
        const new_workers = [];
        for (let i=0; i<workers; i++) {
            new_workers.push(cluster.fork({ CLUSTER_MASTER_PID: process.pid }));
        }
        for (let j=0; j<pids.length; j++) {
            new_workers[j % new_workers.length]
                .send({event: 'outbound.load_pid_queue', data: pids[j]});
        }
        cluster.on('online', worker => {
            Server.lognotice(
                'worker started',
                { worker: worker.id, pid: worker.process.pid }
            );
        });
        cluster.on('listening', (worker, address) => {
            Server.lognotice(`worker ${worker.id} listening on ${endpoint(address)}`);
        });
        cluster.on('exit', cluster_exit_listener);
    });
}

function cluster_exit_listener (worker, code, signal) {
    if (signal) {
        Server.lognotice(`worker ${worker.id} killed by signal ${signal}`);
    }
    else if (code !== 0) {
        Server.lognotice(`worker ${worker.id} exited with error code: ${code}`);
    }
    if (signal || code !== 0) {
        // Restart worker
        const new_worker = cluster.fork({
            CLUSTER_MASTER_PID: process.pid
        });
        new_worker.send({
            event: 'outbound.load_pid_queue', data: worker.process.pid,
        });
    }
}

Server.init_child_respond = (retval, msg) => {
    switch (retval) {
        case constants.ok:
        case constants.cont:
            Server.setup_http_listeners();
            return;
    }

    const pid = process.env.CLUSTER_MASTER_PID;
    Server.logerror(`init_child returned error ${((msg) ? `: ${msg}` : '')}`);
    try {
        if (pid) {
            process.kill(pid);
            Server.logerror(`Killing master (pid=${pid})`);
        }
    }
    catch (err) {
        Server.logerror('Terminating child');
    }
    logger.dump_and_exit(1);
}

/**
 * 在服务器开始监听后，降低进程的权限
 * 以增强服务器安全性， 
 * 将Server.ready 标志设置为1,表示服务器已准备好处理请求
 */
Server.listening = () => {
    const c = Server.cfg.main;

    // Drop privileges
    if (c.group) {
        Server.lognotice(`Switching from current gid: ${process.getgid()}`);
        process.setgid(c.group);
        Server.lognotice(`New gid: ${process.getgid()}`);
    }
    if (c.user) {
        Server.lognotice(`Switching from current uid: ${process.getuid()}`);
        process.setuid(c.user);
        Server.lognotice(`New uid: ${process.getuid()}`);
    }

    Server.ready = 1;
}

/**
 * 在 HTTP 服务器禄始化响应阶段被调用
 * 尝试创建WebSOcket服务器，并对它进行初始化操作
 */
Server.init_http_respond = () => {
    Server.loginfo('init_http_respond');

    let WebSocketServer;
    try { WebSocketServer = require('ws').Server; }
    catch (e) {
        Server.logerror(`unable to load ws.\n  did you: npm install -g ws?`);
        return;
    }

    if (!WebSocketServer) {
        Server.logerror('ws failed to load');
        return;
    }

    Server.http.wss = new WebSocketServer({ server: Server.http.server });
    Server.loginfo('Server.http.wss loaded');

    Server.plugins.run_hooks('init_wss', Server);
}

/**
 * 在WebSocket服务器初始化响应阶段被调用，只输出一条日志
 */
Server.init_wss_respond = () => {
    Server.loginfo('init_wss_respond');
}


/**
 * 获取 HTTP 服务器的文档根目录
 * 默认拼接出 文档根目录 http/html,并设置 Server.http.cfg.docroot
 */
Server.get_http_docroot = () => {
    if (Server.http.cfg.docroot) return Server.http.cfg.docroot;

    Server.http.cfg.docroot = path.join( (process.env.HARAKA || __dirname), 'http', 'html');
    Server.loginfo(`using html docroot: ${Server.http.cfg.docroot}`);
    return Server.http.cfg.docroot;
}

/**
 * 404 错误处理函数
 * @param {*} req 
 * @param {*} res 
 * @returns 
 */
Server.handle404 = (req, res) => {
    // abandon all hope, serve up a 404
    const docroot = Server.get_http_docroot();

    // respond with html page
    if (req.accepts('html')) {
        res.status(404).sendFile('404.html', { root: docroot });
        return;
    }

    // respond with json
    if (req.accepts('json')) {
        res.status(404).send({ err: 'Not found' });
        return;
    }

    res.status(404).send('Not found!');
}
