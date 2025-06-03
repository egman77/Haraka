'use strict';
// Log 类，用于管理日志记录的核心功能
// 引入 Node.js 内置的 util 模块，提供实用工具函数
const util      = require('node:util');
// 引入 Node.js 内置的 tty 模块，用于处理终端相关操作
const tty       = require('node:tty');

// 引入 haraka 配置模块，用于读取配置文件
const config    = require('haraka-config');
// 引入 haraka 常量模块，提供项目中的常量
const constants = require('haraka-constants');

// 声明 plugins 变量，用于存储插件模块
let plugins;

// 用于匹配字符串中是否包含空字符串、空格、等号、双引号或反斜杠的正则表达式
const regex = /(^$|[ ="\\])/;
// 用于替换字符串中双引号和反斜杠的正则表达式
const escape_replace_regex = /["\\]/g;

/**
 * 将对象转换为键值对字符串，用于日志输出
 * @param {Object} obj - 要转换的对象
 * @returns {string} - 转换后的键值对字符串
 */
function stringify (obj) {
    let str = '';
    let key;
    // 遍历对象的所有属性
    for (key in obj) {
        let v = obj[key];
        // 如果属性值为 null 或 undefined，则将其设为空字符串
        if (v == null) {
            str += `${key}="" `;
            continue;
        }
        // 将属性值转换为字符串
        v = v.toString();
        // 如果属性值包含特殊字符，则用双引号包裹并转义特殊字符
        if (regex.test(v)) {
            str += `${key}="${v.replace(escape_replace_regex, '\\$&')}" `;
        }
        else {
            // 否则直接拼接属性名和属性值
            str += `${key}=${v} `;
        }
    }
    // 去除字符串末尾的空格并返回
    return str.trim();
}

// 将 logger 对象导出，供其他模块使用
const logger = exports;

// 定义日志级别，数字越小表示级别越高
logger.levels = {
    DATA:     9,
    PROTOCOL: 8,
    DEBUG:    7,
    INFO:     6,
    NOTICE:   5,
    WARN:     4,
    ERROR:    3,
    CRIT:     2,
    ALERT:    1,
    EMERG:    0,
}
// 获取日志级别的名称数组
const level_names = Object.keys(logger.levels)

// 为 logger.levels 和 logger 对象添加以 LOG 开头的日志级别属性
for (const le in logger.levels) {
    logger.levels[`LOG${le}`] = logger.levels[le];
    logger[`LOG${le}`] = logger.levels[le];
}

// 定义日志输出格式
logger.formats = {
    DEFAULT: "DEFAULT",
    LOGFMT: "LOGFMT",
    JSON: "JSON",
}

// 默认日志级别为 WARN
logger.loglevel      = logger.levels.WARN;
// 默认日志格式为 DEFAULT
logger.format        = logger.formats.DEFAULT;
// 默认不显示时间戳
logger.timestamps    = false;
// 用于存储延迟记录的日志条目
logger.deferred_logs = [];
// 日志记录器的名称
logger.name          = 'logger'

// 定义不同日志级别对应的颜色
logger.colors = {
    "DATA" : "green",
    "PROTOCOL" : "green",
    "DEBUG" : "grey",
    "INFO" : "cyan",
    "NOTICE" : "blue",
    "WARN" : "red",
    "ERROR" : "red",
    "CRIT" : "red",
    "ALERT" : "red",
    "EMERG" : "red",
}

// 检查标准输出是否为终端
const stdout_is_tty = tty.isatty(process.stdout.fd);

/**
 * 初始化日志记录器，加载配置并初始化日志级别和时间戳设置
 */
logger._init = function () {
    // 加载日志配置文件
    this.load_log_ini();
    // 初始化日志级别
    this._init_loglevel();
    // 初始化时间戳设置
    this._init_timestamps();
}

/**
 * 加载 log.ini 配置文件，并根据配置设置日志级别、时间戳和格式
 */
logger.load_log_ini = function () {
    // 读取 log.ini 配置文件，并将 main.timestamps 配置项解析为布尔值
    this.cfg = config.get('log.ini', {
        booleans: [
            '+main.timestamps',
        ]
    },
    () => {
        // 配置文件变化时重新加载
        this.load_log_ini();
    });

    // 根据配置文件设置日志级别
    this.set_loglevel(this.cfg.main.level);
    // 根据配置文件设置时间戳
    this.set_timestamps(this.cfg.main.timestamps);
    // 根据配置文件设置日志格式
    this.set_format(this.cfg.main.format);
}

/**
 * 为字符串添加颜色
 * @param {string} color - 颜色名称
 * @param {string} str - 要添加颜色的字符串
 * @returns {string} - 添加颜色后的字符串
 */
logger.colorize = (color, str) => {
    // 如果颜色名称无效，则直接返回原始字符串
    if (!util.inspect.colors[color]) { return str; } 
    // 使用 ANSI 转义序列为字符串添加颜色
    return `\u001b[${util.inspect.colors[color][0]}m${str}\u001b[${util.inspect.colors[color][1]}m`;
}

/**
 * 处理延迟记录的日志条目，并在处理完成后执行回调函数
 * @param {Function} cb - 处理完成后的回调函数
 * @returns {boolean} - 始终返回 true
 */
logger.dump_logs = cb => {
    // 循环处理延迟记录的日志条目
    while (logger.deferred_logs.length > 0) {
        // 从数组头部取出一个日志条目
        const log_item = logger.deferred_logs.shift();
        // 调用插件的 log 钩子处理日志条目
        plugins.run_hooks('log', logger, log_item);
    }
    // 处理完成后执行回调函数
    if (cb) process.stdout.write('', cb);
    return true;
}

/**
 * 处理延迟记录的日志条目，然后退出进程
 * @param {number|Function} code - 退出码或回调函数
 */
logger.dump_and_exit = function (code) {
    // 处理延迟记录的日志条目
    this.dump_logs(() => {
        // 如果 code 是函数，则执行该函数
        if (typeof code === 'function') return code();
        // 否则退出进程并传入退出码
        process.exit(code);
    });
}

/**
 * 记录日志，根据插件加载情况决定是否立即处理或延迟处理
 * @param {string} level - 日志级别
 * @param {string} data - 日志数据
 * @param {Object} logobj - 日志对象
 * @returns {boolean} - 始终返回 true
 */
logger.log = (level, data, logobj) => {
    // 如果日志级别为 PROTOCOL，则替换换行符
    if (level === 'PROTOCOL') {
        data = data.replace(/\n/g, '\\n');
    }
    // 替换回车符和行尾换行符
    data = data.replace(/\r/g, '\\r').replace(/\n$/, '');

    // 创建日志条目对象
    const item = { level, data, obj: logobj};

    // 检查插件列表是否为空
    const emptyPluginList = !plugins || Array.isArray(plugins.plugin_list) && !plugins.plugin_list.length;
    if (emptyPluginList) {
        // 如果插件列表为空，则将日志条目添加到延迟记录数组中
        logger.deferred_logs.push(item);
        return true;
    }

    // 处理延迟记录的日志条目
    while (logger.deferred_logs.length > 0) {
        const log_item = logger.deferred_logs.shift();
        plugins.run_hooks('log', logger, log_item);
    }

    // 调用插件的 log 钩子处理当前日志条目
    plugins.run_hooks('log', logger, item);
    return true;
}

/**
 * 根据返回值和日志数据输出日志信息
 * @param {number} retval - 返回值
 * @param {string} msg - 日志消息
 * @param {Object} data - 日志数据
 * @returns {boolean} - 如果返回值为 constants.cont 则返回 true，否则返回 false
 */
logger.log_respond = (retval, msg, data) => {
    // 如果返回值不是 constants.cont，则不处理
    if (retval !== constants.cont) return false;

    let timestamp_string = '';
    // 如果启用了时间戳，则添加时间戳字符串
    if (logger.timestamps) timestamp_string = `${new Date().toISOString()} `;

    // 获取日志级别对应的颜色
    const color = logger.colors[data.level];
    if (color && stdout_is_tty) {
        // 如果标准输出是终端且颜色有效，则输出带颜色的日志信息
        process.stdout.write(`${timestamp_string}${logger.colorize(color,data.data)}\n`);
    }
    else {
        // 否则输出普通日志信息
        process.stdout.write(`${timestamp_string}${data.data}\n`);
    }

    return true;
}

/**
 * 设置日志级别
 * @param {string|number} level - 日志级别，可以是字符串或数字
 */
logger.set_loglevel = function (level) {
    // 如果 level 为 undefined 或 null，则不处理
    if (level === undefined || level === null) return;

    // 将 level 转换为数字
    const loglevel_num = parseInt(level);
    if (typeof level === 'string') {
        // 如果 level 是字符串，则记录日志并设置日志级别
        this.log('INFO', `loglevel: ${level.toUpperCase()}`);
        logger.loglevel = logger.levels[level.toUpperCase()];
    }
    else {
        // 否则直接设置日志级别
        logger.loglevel = loglevel_num;
    }

    // 如果日志级别不是整数，则记录警告日志并设置为默认级别
    if (!Number.isInteger(logger.loglevel)) {
        this.log('WARN', `invalid loglevel: ${level} defaulting to LOGWARN`);
        logger.loglevel = logger.levels.WARN;
    }
}

/**
 * 设置日志输出格式
 * @param {string} format - 日志格式名称
 */
logger.set_format = function (format) {
    if (format) {
        // 如果 format 存在，则设置日志格式并记录日志
        logger.format = logger.formats[format.toUpperCase()];
        this.log('INFO', `log format: ${format.toUpperCase()}`);
    }
    else {
        // 否则将日志格式设为 null
        logger.format = null;
    }
    // 如果日志格式无效，则记录警告日志并设置为默认格式
    if (!logger.format) {
        this.log('WARN', `invalid log format: ${format} defaulting to DEFAULT`);
        logger.format = logger.formats.DEFAULT;
    }
}

/**
 * 初始化日志级别，从配置文件中读取日志级别并设置
 */
logger._init_loglevel = function () {
    // 从配置文件中读取日志级别
    const _loglevel = config.get('loglevel', 'value', () => {
        // 配置文件变化时重新初始化日志级别
        this._init_loglevel();
    });

    // 设置日志级别
    this.set_loglevel(_loglevel);
}

/**
 * 检查当前日志级别是否允许记录指定级别的日志
 * @param {number} level - 要检查的日志级别
 * @returns {boolean} - 如果允许记录则返回 true，否则返回 false
 */
logger.would_log = level => {
    if (logger.loglevel < level) return false;
    return true;
}

/**
 * 设置是否显示时间戳
 * @param {boolean} value - 是否显示时间戳
 */
logger.set_timestamps = value => {
    logger.timestamps = !!value;
}

/**
 * 初始化时间戳设置，从配置文件中读取时间戳设置并设置
 */
logger._init_timestamps = function () {
    // 从配置文件中读取时间戳设置
    const _timestamps = config.get('log_timestamps', 'value', () => {
        // 配置文件变化时重新初始化时间戳设置
        this._init_timestamps();
    });

    // 如果配置文件中设置了时间戳，则启用时间戳
    this.set_timestamps(logger.timestamps || _timestamps);
}

// 初始化日志记录器
logger._init();

/**
 * 根据日志级别记录日志的高阶函数
 * @param {string} level - 日志级别
 * @param {string} key - 日志级别对应的键
 * @param {string} origin - 日志来源
 * @returns {Function} - 用于记录日志的函数
 */
logger.log_if_level = (level, key, origin) => function () {
    // 如果当前日志级别低于指定级别，则不记录日志
    if (logger.loglevel < logger[key]) return;

    // 初始化日志对象
    let logobj = {
        level,
        uuid: '-',
        origin: (origin || 'core'),
        message: ''
    };

    // 遍历传入的参数，构建日志对象
    for (const data of arguments) {
        if (typeof data !== 'object') {
            // 如果参数不是对象，则直接添加到消息中
            logobj.message += (data);
            continue;
        }
        if (!data) continue;

        // 如果对象是 Connection 类型，则添加连接 ID
        if (data.constructor?.name === 'Connection') {
            logobj.uuid = data.uuid;
            if (data.tran_count > 0) logobj.uuid += `.${data.tran_count}`;
        }
        // 如果对象是插件实例，则设置日志来源为插件名称
        else if (data instanceof plugins.Plugin) {
            logobj.origin = data.name;
        }
        // 处理 outbound 相关对象
        else if (Object.hasOwn(data, 'name')) { 
            logobj.origin = data.name;
            if (Object.hasOwn(data, 'uuid')) logobj.uuid = data.uuid;
            if (data.todo?.uuid) logobj.uuid = data.todo.uuid; 
        }
        // 如果日志格式为 LOGFMT 且对象为普通对象，则合并对象
        else if (
            logger.format === logger.formats.LOGFMT && data.constructor === Object) {
            logobj = Object.assign(logobj, data);
        }
        // 如果日志格式为 JSON 且对象为普通对象，则合并对象
        else if (
            logger.format === logger.formats.JSON && data.constructor === Object) {
            logobj = Object.assign(logobj, data);
        }
        // 处理 outbound/client_pool 相关对象
        else if (Object.hasOwn(data, 'uuid')) { 
            logobj.uuid = data.uuid;
        }
        // 如果对象是普通对象，则将其转换为字符串添加到消息中
        else if (data.constructor === Object) {
            if (!logobj.message.endsWith(' ')) logobj.message += ' ';
            logobj.message += (stringify(data));
        }
        else {
            // 否则将对象转换为字符串添加到消息中
            logobj.message += (util.inspect(data));
        }
    }

    // 根据日志格式输出日志
    switch (logger.format) {
        case logger.formats.LOGFMT:
            logger.log(
                level,
                stringify(logobj)
            );
            break
        case logger.formats.JSON:
            logger.log(
                level,
                JSON.stringify(logobj)
            );
            break
        case logger.formats.DEFAULT:
        default:
            logger.log(
                level,
                `[${logobj.level}] [${logobj.uuid}] [${logobj.origin}] ${logobj.message}`
            );
    }
    return true;
}

/**
 * 为对象或类原型添加日志方法
 * @param {Object|Function} object - 要添加日志方法的对象或类
 * @param {string} logName - 日志来源名称
 */
logger.add_log_methods = (object, logName) => {
    if (!object) return

    if (typeof object === 'function') {
        // 如果 object 是函数，则为类原型添加日志方法
        for (const level of level_names.map(l => l.toLowerCase())) {
            object.prototype[`log${level}`] = (function (level) {
                return function () {
                    // 调用 logger 对应的日志方法
                    logger[level].apply(logger, [ this, ...arguments ]);
                };
            })(`log${level}`);
        }
    }
    else if (typeof object === 'object') {
        // 如果 object 是对象，则为对象添加日志方法
        for (const level of level_names) {
            // 对象的日志方法名称，如 loginfo, logwarn 等
            const fnNames = [`log${level.toLowerCase()}`]

            // 如果对象是 logger 本身，则添加短名称的日志方法
            if (Object.hasOwn(object, 'name') && object.name === 'logger') {
                fnNames.push(level.toLowerCase())
            }

            for (const fnName of fnNames) {
                // 如果对象已经有该方法，则跳过
                if (Object.hasOwn(object, fnName)) continue; 
                // 为对象添加日志方法
                object[fnName] = logger.log_if_level(level, `LOG${level}`, logName);
            }
        }
    }
}

// 为 logger 自身添加日志方法
logger.add_log_methods(logger);

// 加载插件模块，确保在所有日志方法编译完成后加载
plugins = require('./plugins');
