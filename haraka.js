#!/usr/bin/env node
// ^ Shebang，指定脚本由 node 执行

'use strict';
// 启用严格模式，有助于捕获常见的编码错误

const path = require('path');
// 导入 'path' 模块，用于处理和转换文件路径

const makePathJoin = () => path.join(process.env.HARAKA, 'node_modules');
// 定义一个函数，用于构建到 Haraka node_modules 目录的路径
// process.env.HARAKA 应该指向 Haraka 的安装目录

if (!process.env.HARAKA) {
    // 如果 HARAKA 环境变量未设置，则发出警告
    // 这通常意味着 Haraka 可能不是通过标准方式安装或启动的
    console.warn("WARNING: Not running installed Haraka - command line arguments ignored")
}

// this must be set before "server.js" is loaded
// 在加载 'server.js' 之前必须设置 HARAKA 环境变量
process.env.HARAKA = process.env.HARAKA || path.resolve('.');
// 如果 HARAKA 环境变量未设置，则默认为当前工作目录

try {
    // 尝试将 Haraka 的 node_modules 目录添加到 Node.js 的模块搜索路径中
    // 这是为了确保 Haraka 能够找到其依赖的模块
    require.paths.push(makePathJoin());
}
catch (e) {
    // 如果 `require.paths.push` 不可用 (较新版本的 Node.js 中已移除)
    // 则回退到修改 NODE_PATH 环境变量，并重新初始化模块路径
    process.env.NODE_PATH = process.env.NODE_PATH ?
        (`${process.env.NODE_PATH}:${makePathJoin()}`) :
        (makePathJoin());
    require('module')._initPaths(); // Horrible hack - 这是一个非标准的、可能不稳定的 hack
}

const utils = require('haraka-utils');
// 导入 'haraka-utils' 模块，提供各种实用函数

const logger = require('./logger');
// 导入本地的 'logger.js' 模块，用于日志记录

logger.notice(`logger start in pid:${process.pid}:========================>`);

const server = require('./server');
// 导入本地的 'server.js' 模块，负责服务器的核心逻辑

exports.version = utils.getVersion(__dirname)
// 从 'haraka-utils' 获取版本信息并导出

process.on('uncaughtException', err => {
    // 注册未捕获异常的处理器
    // 当代码中抛出未被 try...catch 捕获的错误时，此事件会被触发
    if (err.stack) {
        // 如果错误对象有堆栈信息，则逐行记录
        err.stack.split("\n").forEach(line => logger.crit(line));
    }
    else {
        // 否则，记录序列化后的错误对象
        logger.crit(`Caught exception: ${JSON.stringify(err)}`);
    }
    logger.dump_and_exit(1);
    // 记录所有缓冲的日志并以错误码 1 退出进程
});

let shutting_down = false;
// 标记服务器是否正在关闭过程中

const signals = ['SIGINT'];
// 定义需要处理的信号列表，首先是 SIGINT (通常由 Ctrl+C 触发)

if (process.pid === 1) signals.push('SIGTERM')
// 如果进程 ID 为 1 (通常意味着它是在 Docker 容器中作为主进程运行)
// 则也处理 SIGTERM 信号，这是容器编排系统用来正常停止容器的信号

for (const sig of signals) {
    logger.notice(`logger start pdi:${process.pid} in sig:${sig} :========`);
    // 遍历定义的信号列表
    process.on(sig, () => {
        // 为每个信号注册处理器
        if (shutting_down) return process.exit(1);
        // 如果已经在关闭过程中，则强制退出以避免重复处理

        shutting_down = true;
        // 标记服务器开始关闭

        const [, filename] = process.argv;
        // 获取当前执行的脚本文件名

        process.title = path.basename(filename, '.js');
        // 设置进程标题 (在 'ps' 或 'top' 命令中可见)

        logger.notice(`${sig} received`);
        // 记录收到信号的信息

        logger.dump_and_exit(() => {
            // 记录所有缓冲的日志并执行回调后退出
            if (server.cluster?.isMaster) {
                // 如果使用了 Node.js 的 cluster 模块并且当前是主进程
                server.performShutdown();
                // 调用服务器的关闭逻辑
            }
            else if (!server.cluster) {
                // 如果没有使用 cluster 模块 (单进程模式)
                server.performShutdown();
                // 调用服务器的关闭逻辑
            }
            // 注意：在 cluster 模式下，工作进程收到信号后会自行退出，主进程负责关闭
        });
    });
}

process.on('SIGHUP', () => {
    // 注册 SIGHUP 信号的处理器
    // SIGHUP 通常用于通知守护进程重新加载配置或执行其他特定操作
    logger.notice('Flushing the temp fail queue');
    // 记录刷新临时失败队列的消息
    server.flushQueue();
    // 调用服务器的刷新队列功能 (可能是用于重试发送失败的邮件)
});

process.on('exit', code => {
    // 注册进程退出时的处理器
    if (shutting_down) return;
    // 如果是正常关闭流程 (shutting_down 为 true)，则不执行此处的逻辑
    // 这是为了处理意外退出的情况

    const [, filename] = process.argv;
    process.title = path.basename(filename, '.js');

    logger.notice('Shutting down');
    // 记录正在关闭的消息
    logger.dump_logs();
    // 记录所有缓冲的日志
});

logger.log('NOTICE', `hdh: Starting up Haraka version ${exports.version}`);
// 记录 Haraka 启动及其版本号

server.createServer();
// 调用 'server.js' 中的 createServer 函数，实际启动 Haraka 服务器
