var require = function (file, cwd) {
    var resolved = require.resolve(file, cwd || '/');
    var mod = require.modules[resolved];
    if (!mod) throw new Error(
        'Failed to resolve module ' + file + ', tried ' + resolved
    );
    var res = mod._cached ? mod._cached : mod();
    return res;
}

require.paths = [];
require.modules = {};
require.extensions = [".js",".coffee"];

require._core = {
    'assert': true,
    'events': true,
    'fs': true,
    'path': true,
    'vm': true
};

require.resolve = (function () {
    return function (x, cwd) {
        if (!cwd) cwd = '/';
        
        if (require._core[x]) return x;
        var path = require.modules.path();
        cwd = path.resolve('/', cwd);
        var y = cwd || '/';
        
        if (x.match(/^(?:\.\.?\/|\/)/)) {
            var m = loadAsFileSync(path.resolve(y, x))
                || loadAsDirectorySync(path.resolve(y, x));
            if (m) return m;
        }
        
        var n = loadNodeModulesSync(x, y);
        if (n) return n;
        
        throw new Error("Cannot find module '" + x + "'");
        
        function loadAsFileSync (x) {
            if (require.modules[x]) {
                return x;
            }
            
            for (var i = 0; i < require.extensions.length; i++) {
                var ext = require.extensions[i];
                if (require.modules[x + ext]) return x + ext;
            }
        }
        
        function loadAsDirectorySync (x) {
            x = x.replace(/\/+$/, '');
            var pkgfile = x + '/package.json';
            if (require.modules[pkgfile]) {
                var pkg = require.modules[pkgfile]();
                var b = pkg.browserify;
                if (typeof b === 'object' && b.main) {
                    var m = loadAsFileSync(path.resolve(x, b.main));
                    if (m) return m;
                }
                else if (typeof b === 'string') {
                    var m = loadAsFileSync(path.resolve(x, b));
                    if (m) return m;
                }
                else if (pkg.main) {
                    var m = loadAsFileSync(path.resolve(x, pkg.main));
                    if (m) return m;
                }
            }
            
            return loadAsFileSync(x + '/index');
        }
        
        function loadNodeModulesSync (x, start) {
            var dirs = nodeModulesPathsSync(start);
            for (var i = 0; i < dirs.length; i++) {
                var dir = dirs[i];
                var m = loadAsFileSync(dir + '/' + x);
                if (m) return m;
                var n = loadAsDirectorySync(dir + '/' + x);
                if (n) return n;
            }
            
            var m = loadAsFileSync(x);
            if (m) return m;
        }
        
        function nodeModulesPathsSync (start) {
            var parts;
            if (start === '/') parts = [ '' ];
            else parts = path.normalize(start).split('/');
            
            var dirs = [];
            for (var i = parts.length - 1; i >= 0; i--) {
                if (parts[i] === 'node_modules') continue;
                var dir = parts.slice(0, i + 1).join('/') + '/node_modules';
                dirs.push(dir);
            }
            
            return dirs;
        }
    };
})();

require.alias = function (from, to) {
    var path = require.modules.path();
    var res = null;
    try {
        res = require.resolve(from + '/package.json', '/');
    }
    catch (err) {
        res = require.resolve(from, '/');
    }
    var basedir = path.dirname(res);
    
    var keys = (Object.keys || function (obj) {
        var res = [];
        for (var key in obj) res.push(key)
        return res;
    })(require.modules);
    
    for (var i = 0; i < keys.length; i++) {
        var key = keys[i];
        if (key.slice(0, basedir.length + 1) === basedir + '/') {
            var f = key.slice(basedir.length);
            require.modules[to + f] = require.modules[basedir + f];
        }
        else if (key === basedir) {
            require.modules[to] = require.modules[basedir];
        }
    }
};

require.define = function (filename, fn) {
    var dirname = require._core[filename]
        ? ''
        : require.modules.path().dirname(filename)
    ;
    
    var require_ = function (file) {
        return require(file, dirname)
    };
    require_.resolve = function (name) {
        return require.resolve(name, dirname);
    };
    require_.modules = require.modules;
    require_.define = require.define;
    var module_ = { exports : {} };
    
    require.modules[filename] = function () {
        require.modules[filename]._cached = module_.exports;
        fn.call(
            module_.exports,
            require_,
            module_,
            module_.exports,
            dirname,
            filename
        );
        require.modules[filename]._cached = module_.exports;
        return module_.exports;
    };
};

if (typeof process === 'undefined') process = {};

if (!process.nextTick) process.nextTick = (function () {
    var queue = [];
    var canPost = typeof window !== 'undefined'
        && window.postMessage && window.addEventListener
    ;
    
    if (canPost) {
        window.addEventListener('message', function (ev) {
            if (ev.source === window && ev.data === 'browserify-tick') {
                ev.stopPropagation();
                if (queue.length > 0) {
                    var fn = queue.shift();
                    fn();
                }
            }
        }, true);
    }
    
    return function (fn) {
        if (canPost) {
            queue.push(fn);
            window.postMessage('browserify-tick', '*');
        }
        else setTimeout(fn, 0);
    };
})();

if (!process.title) process.title = 'browser';

if (!process.binding) process.binding = function (name) {
    if (name === 'evals') return require('vm')
    else throw new Error('No such module')
};

if (!process.cwd) process.cwd = function () { return '.' };

if (!process.env) process.env = {};
if (!process.argv) process.argv = [];

require.define("path", function (require, module, exports, __dirname, __filename) {
function filter (xs, fn) {
    var res = [];
    for (var i = 0; i < xs.length; i++) {
        if (fn(xs[i], i, xs)) res.push(xs[i]);
    }
    return res;
}

// resolves . and .. elements in a path array with directory names there
// must be no slashes, empty elements, or device names (c:\) in the array
// (so also no leading and trailing slashes - it does not distinguish
// relative and absolute paths)
function normalizeArray(parts, allowAboveRoot) {
  // if the path tries to go above the root, `up` ends up > 0
  var up = 0;
  for (var i = parts.length; i >= 0; i--) {
    var last = parts[i];
    if (last == '.') {
      parts.splice(i, 1);
    } else if (last === '..') {
      parts.splice(i, 1);
      up++;
    } else if (up) {
      parts.splice(i, 1);
      up--;
    }
  }

  // if the path is allowed to go above the root, restore leading ..s
  if (allowAboveRoot) {
    for (; up--; up) {
      parts.unshift('..');
    }
  }

  return parts;
}

// Regex to split a filename into [*, dir, basename, ext]
// posix version
var splitPathRe = /^(.+\/(?!$)|\/)?((?:.+?)?(\.[^.]*)?)$/;

// path.resolve([from ...], to)
// posix version
exports.resolve = function() {
var resolvedPath = '',
    resolvedAbsolute = false;

for (var i = arguments.length; i >= -1 && !resolvedAbsolute; i--) {
  var path = (i >= 0)
      ? arguments[i]
      : process.cwd();

  // Skip empty and invalid entries
  if (typeof path !== 'string' || !path) {
    continue;
  }

  resolvedPath = path + '/' + resolvedPath;
  resolvedAbsolute = path.charAt(0) === '/';
}

// At this point the path should be resolved to a full absolute path, but
// handle relative paths to be safe (might happen when process.cwd() fails)

// Normalize the path
resolvedPath = normalizeArray(filter(resolvedPath.split('/'), function(p) {
    return !!p;
  }), !resolvedAbsolute).join('/');

  return ((resolvedAbsolute ? '/' : '') + resolvedPath) || '.';
};

// path.normalize(path)
// posix version
exports.normalize = function(path) {
var isAbsolute = path.charAt(0) === '/',
    trailingSlash = path.slice(-1) === '/';

// Normalize the path
path = normalizeArray(filter(path.split('/'), function(p) {
    return !!p;
  }), !isAbsolute).join('/');

  if (!path && !isAbsolute) {
    path = '.';
  }
  if (path && trailingSlash) {
    path += '/';
  }
  
  return (isAbsolute ? '/' : '') + path;
};


// posix version
exports.join = function() {
  var paths = Array.prototype.slice.call(arguments, 0);
  return exports.normalize(filter(paths, function(p, index) {
    return p && typeof p === 'string';
  }).join('/'));
};


exports.dirname = function(path) {
  var dir = splitPathRe.exec(path)[1] || '';
  var isWindows = false;
  if (!dir) {
    // No dirname
    return '.';
  } else if (dir.length === 1 ||
      (isWindows && dir.length <= 3 && dir.charAt(1) === ':')) {
    // It is just a slash or a drive letter with a slash
    return dir;
  } else {
    // It is a full dirname, strip trailing slash
    return dir.substring(0, dir.length - 1);
  }
};


exports.basename = function(path, ext) {
  var f = splitPathRe.exec(path)[2] || '';
  // TODO: make this comparison case-insensitive on windows?
  if (ext && f.substr(-1 * ext.length) === ext) {
    f = f.substr(0, f.length - ext.length);
  }
  return f;
};


exports.extname = function(path) {
  return splitPathRe.exec(path)[3] || '';
};

});

require.define("/lib/dht.js", function (require, module, exports, __dirname, __filename) {

//var dgram = require('dgram');

var util = require('./util');
var consts = require('./consts');
var rtable = require('./rtable');
var traverse = require('./traverse');
var rpc = require('./rpc');
var cache = require('./cache');
var bencode = require('dht-bencode');

exports.setDebug = util.setDebug;
exports.util = util;
exports.consts = consts;

function renew_token(dht) {
	dht.token.push( util.generate_id() );
	if (dht.token.length > 3) dht.token.shift();
}

function DHT(port) {
	var s4, s6;

	this.started = false;

	this.id = util.generate_id();

	//this.socket4 = s4 = dgram.createSocket('udp4');
	//s4.bind(port || 0);
	//this.port = s4.address().port;

// 	this.socket6 = s6 = dgram.createSocket('udp6');
// 	s6.bind(this.port, "::");

	/* nodes that expect a response, key: address + '/' + port */
	this.active_nodes = {};

	this.rtable = new rtable.RoutingTable(this);

	this.cache = new cache.Cache();

	this.version = "Node.JS";

	this.token = [ util.generate_id() ];
	this.token_intervalID = setInterval(renew_token, 5*60*1000, this);
}

exports.DHT = DHT;

DHT.prototype.start = function start() {
	if (this.started) return;
	this.started = true;

	this.socket4.on('message', this._recv.bind(this));
// 	this.socket6.on('message', this._recv.bind(this));

	this.rtable.start();
	this.cache.start();
}

DHT.prototype.stop = function start() {
	if (!this.started) return;
	this.started = false;

	this.socket4.removeAllListeners('message');
// 	this.socket6.removeAllListeners('message');

	this.rtable.stop();
	this.cache.stop();
}


DHT.prototype._get_node = function _get_node(address, port, id) {
	var n, key = address + '/' + port;

	n = this.active_nodes[key];
	if (n) return n;

	this.active_nodes[key] = n = new (rpc.Node)(this, address, port, id);
	return n;
}

DHT.prototype._send = function send(address, port, message) {
	var buf;
	message.v = this.version;
	util.debug('Sending (to undefined:undefined): undefined', address, port, message);
	try {
		buf = bencode.bencode(message);
		this.socket4.send(buf, 0, buf.length, port, address);
	} catch (e) {
		console.log("Couldn't send: undefined", e.stack);
	}
}

DHT.prototype._recv = function recv(msg, rinfo) {
	var data, query, node;

	try {
		data = bencode.bdecode(msg);
	} catch (e) {
		console.log("Couldn't decode message (from undefined:undefined) undefined: undefined", rinfo.address, rinfo.port, msg, e);
		return;
	}
	util.debug('Receiving (from undefined): undefined', rinfo, data);
	if (data) {
		/* check message type */
		if (!data.y || !(data.y instanceof Buffer)) return; /* ignore */
		data.y = data.y.toString('ascii');
		if (data.y != 'r' && data.y != 'e' && data.y != 'q') return; /* ignore */

		/* check transaction id */
		if (!data.t || !(data.t instanceof Buffer)) return; /* ignore */

		if (data.y == 'q') {
			query = new rpc.Query(this, rinfo.address, rinfo.port, data);
			query.handle(data);
		} else {
			node = this.active_nodes[rinfo.address + "/" + rinfo.port];
			if (node) node.recv(data);
		}
	}
}

DHT.prototype.getToken = function getToken(address, port) {
	var curtoken = this.token[this.token.length-1];
	return sha1(curtoken.toString('base64') + address + "/" + port);
}

DHT.prototype.verifyToken = function verifyToken(address, port, token) {
	var b64 = token.toString('base64');
	for (var i in this.token) {
		if (b64 == sha1(this.token[i].toString('base64') + address + "/" + port, 'base64')) return true;
	}
	return false;
}

DHT.prototype.lookup = function lookup(info_hash, callback) {
	var t = new traverse.Traversal(this, info_hash, traverse.traverse_get_peers, function() {
		callback(t.peers, true);
	});
	t.peer_callback = function(peers) {
		callback(peers, false);
	}
	t.max_requests += 100;
	t.start();
}

DHT.prototype.announce = function announce(info_hash, port) {
	var t = new traverse.Traversal(this, target, traverse.traverse_get_peers, function() {
		var i, l, n;
		if (!t.nodes) {
			util.debug("couldn't find any node to announce 'undefined' @ undefined", info_hash, port);
			return;
		}
		for (i = 0, l = t.nodes.length; i < l; ++i) {
			n = this.nodes[i];
			this._announce_peer(n.address, n.port, n.id, info_hash, port, n.token, function() { });
		}
	}.bind(this));
	t.max_requests += 100;
	t.start();
}

DHT.prototype._ping = function _ping(address, port, id, callback) {
	var node = this._get_node(address, port, id);
	node.query({ 'q': 'ping' }, callback);
}

DHT.prototype._find_node = function _find_node(address, port, id, target, callback) {
	var node = this._get_node(address, port, id);
	node.query({ 'q': 'find_node', 'a': { 'target': target } }, callback);
}

DHT.prototype._get_peers = function _get_peers(address, port, id, info_hash, callback) {
	var node = this._get_node(address, port, id);
	node.query({ 'q': 'get_peers', 'a': { 'info_hash': info_hash } }, callback);
}

DHT.prototype._announce_peer = function _announce_peer(address, port, id, info_hash, myport, token, callback) {
	var node = this._get_node(address, port, id);
	node.query({ 'q': 'announce_peer', 'a': { 'info_hash': info_hash, 'port': myport, 'token': token } }, callback);
}

DHT.prototype._refresh = function _refresh(target) {
	var t = new traverse.Traversal(this, target, traverse.traverse_refresh, function() {});
	t.start();
}

DHT.prototype.bootstrap = function bootstrap(nodes) {
	var t = new traverse.Traversal(this, this.id, traverse.traverse_refresh, function() {});
	t.add_list(nodes);
	t.max_requests += nodes.length;
	t.start();
}

});

require.define("/lib/util.js", function (require, module, exports, __dirname, __filename) {

var crypto = require('crypto');

exports.debug = false;

function setDebug() {
	if (arguments.length > 0) {
		exports.debug = !!arguments[0];
	}
	return exports.debug;
}
exports.setDebug = setDebug;

function debug() {
	if (exports.debug) {
		console.log.apply(this, arguments);
	}
}
exports.debug = debug;

function buf2hex(buf) {
	var i, l, s, c;
	var hex = "0123456789abcdef";

	if (this instanceof Buffer) buf = this;

	s = "";
	for (i = 0, l = this.length; i < l; ++i) {
		c = this[i];
		if (c == 92) { /* \ */
			s += "\\\\";
		} else if (c >= 32 && c < 128) {
			s += String.fromCharCode(c);
		} else {
			s += "\\x" + hex[(c / 16) | 0] + hex[c % 16];
		}
	}
	return s;
}
exports.buf2hex = buf2hex;

if (!Buffer.prototype.toJSON) {
	Buffer.prototype.toJSON = buf2hex;
}

function hex2buf(s) {
	var buf = new Buffer(s.length >> 1), pos, x;
	for (pos = 0; pos < buf.length; ++pos) {
		buf[pos] = parseInt(s.slice(2*pos, 2*pos+2), 16);
	}
	return buf;
}
exports.hex2buf = hex2buf;

function array_append(a) {
	var i, l;
	for (i = 1, l = arguments.length; i < l; ++i) {
		a.push.apply(a, arguments[i]);
	}
}
exports.array_append = array_append;

/* returns seconds */
function time_now() {
	var d = new Date();
	return (d.getTime() / 1000);
}
exports.time_now = time_now;

/* encoding: 'binary' (default), 'hex', 'base64' */
function sha1(data, encoding) {
	var hash = crypto.createHash('sha1');
	hash.update(data);
	if (!encoding || encoding === 'binary') {
		return new Buffer(hash.digest('base64'), 'base64');
	} else {
		return hash.digest(encoding);
	}
}
exports.sha1 = sha1;

function buf_dup(b) {
	var r = new Buffer(b.length);
	b.copy(r, 0, 0, b.length);
	return r;
}
exports.buf_dup = buf_dup;

var id_dup = buf_dup;
exports.id_dup = id_dup;

function id_cmp(a, b) {
	var i, x, y;
	for (i = 0; i < 20; ++i) {
		x = a[i];
		y = b[i];
		if (x < y) return -1;
		if (x > y) return 1;
	}
	return 0; /* equal */
}
exports.id_cmp = id_cmp;

function id_lt(a, b) {
	return -1 === id_cmp(a, b);
}
exports.id_lt = id_lt;
function id_gt(a, b) {
	return  1 === id_cmp(a, b);
}
exports.id_gt = id_gt;
function id_eq(a, b) {
	return  0 === id_cmp(a, b);
}
exports.id_eq = id_eq;

function id_xor(a, b) {
	var i, r = new Buffer(20);
	for (i = 0; i < 20; i++) {
		r[i] = a[i] ^ b[i];
	}
	return r;
}
exports.id_xor = id_xor;

function id_common(a, b) {
	var i, j, x;

	for (i = 0; i < 20; i++) {
		if (a[i] !== b[i]) {
			x = a[i] ^ b[i];
			i = i * 8;
			for (j = 128; j > 0; j >>= 1, i++) {
				if (x & j) return i;
			}
			/* shouldn't end here: at least one bit must be set */
			throw new Error("bad");
		}
	}
	return 160; /* equal */
}
exports.id_common = id_common;

function id_random_with_prefix(id, prefixlen) {
	var r = generate_id(), i, mask;
	i = 0;
	for ( ; prefixlen >= 8; prefixlen -= 8, ++i) {
		r[i] = id[i];
	}
	if (prefixlen > 0) {
		mask = (256 >> prefixlen) - 1;
		r[i] = (id[i] & (255 ^ mask)) | (r[i] & mask);
	}
	return r;
}
exports.id_random_with_prefix = id_random_with_prefix;

function generate_id() {
	return sha1(Math.random().toString());
}
exports.generate_id = generate_id;

function generate_tid() {
	return Math.floor(Math.random() * 65536) % 65536;
}
exports.generate_tid = generate_tid;

function tid_to_buffer(tid) {
	return new Buffer([Math.floor(tid / 256), tid % 256]);
}
exports.tid_to_buffer = tid_to_buffer;

function buffer_to_tid(b) {
	if (b.length !== 2) return -1;
	return b[0] * 256 + b[1];
}
exports.buffer_to_tid = buffer_to_tid;

/* callback(mode, [other results]): mode = 0: regular result, 1: short timeout, 2: late result */
function short_timeout(timeout, callback) {
	var done = false, late = false;
	var id = setTimeout(function() {
		if (done) return;
		late = true;
		callback(1);
	}, timeout);

	return function() {
		var l;
		if (done) return;
		done = true;
		clearTimeout(id);
		l = Array.prototype.slice.call(arguments);
		l.unshift(late ? 2 : 0);
		callback.apply(null, l);
	};
}
exports.short_timeout = short_timeout;

function decode_node_info(nodes) {
	var i, id, address, port, l;

	if (!nodes || !(nodes instanceof Buffer)) return null;

	if (nodes.length % 26 !== 0) return null;

	l = [];
	for (i = 0; i < nodes.length; i += 26) {
		id = buf_dup(nodes.slice(i, i+20));
		address = [ nodes[i+20], nodes[i+21], nodes[i+22], nodes[i+23] ].join('.');
		port = nodes[i+24] * 256 + nodes[i+25];
		l.push({ address: address, port: port, id: id });
	}

	return l;
}
exports.decode_node_info = decode_node_info;

function encode_node_info(nodes) {
	var buf, pos, i, l, n, a;

	buf = new Buffer(nodes.length * 26);
	for (pos = 0, i = 0, l = nodes.length; i < l; i++, pos+=26) {
		n = nodes[i];
		n.id.copy(buf, pos, 0, 20);
		a = n.address.split('.');
		buf[pos+20] = a[0] | 0; buf[pos+21] = a[1] | 0; buf[pos+22] = a[2] | 0; buf[pos+23] = a[3] | 0;
		buf[pos+24] = (n.port/256) | 0; buf[pos+25] = (n.port % 256);
	}

	return buf;
}
exports.encode_node_info = encode_node_info;

function decode_peer_info(peer) {
	var i, address, port;

	if (!peer || !(peer instanceof Buffer)) return null;

	if (peer.length !== 6) return null;

	address = [ peer[0], peer[1], peer[2], peer[3] ].join('.');
	port = peer[4] * 256 + peer[5];
	return { address: address, port: port };
}
exports.decode_peer_info = decode_peer_info;

function encode_peer_info(peer) {
	var buf, a;

	buf = new Buffer(6);
	a = peer.address.split('.');
	buf[0] = a[0] | 0; buf[1] = a[1] | 0; buf[2] = a[2] | 0; buf[3] = a[3] | 0;
	buf[4] = (n.port/256) | 0; buf[5] = (n.port % 256);

	return buf;
}
exports.encode_peer_info = encode_peer_info;

function compare_nodes_for(target) {
	return function compares_nodes_for_target(a, b) {
		var i, x, y, t;
		for (i = 0; i < 20; ++i) {
			x = a[i]; y = b[i];
			if (x === y) continue;
			t = target[i];
			return (x ^ t) - (y ^ t);
		}
		return 0;
	}
}
exports.compare_nodes_for = compare_nodes_for;

function accumulate_nodes(nodes, target, node, max) {
	var cmp, i, l, nid;

	if (node.id) {
		cmp = compare_nodes_for(target);
		for (i = 0, l = nodes.length; i < l; ++i) {
			nid = nodes[i].id;
			if (!nid || cmp(node.id, nid) < 0) {
				nodes.splice(i, 0, node);
				if (max && nodes.length > max) nodes.splice(max);
				return;
			}
		}
	}

	if (!max || nodes.length < max) nodes.push(node);
}
exports.accumulate_nodes = accumulate_nodes;

});

require.define("crypto", function (require, module, exports, __dirname, __filename) {
module.exports = require("crypto-browserify")
});

require.define("/node_modules/crypto-browserify/package.json", function (require, module, exports, __dirname, __filename) {
module.exports = {}
});

require.define("/node_modules/crypto-browserify/index.js", function (require, module, exports, __dirname, __filename) {
var sha = require('./sha')

var algorithms = {
  sha1: {
    hex: sha.hex_sha1,
    binary: sha.b64_sha1,
    ascii: sha.str_sha1
  }
}

function error () {
  var m = [].slice.call(arguments).join(' ')
  throw new Error([
    m,
    'we accept pull requests',
    'http://github.com/dominictarr/crypto-browserify'
    ].join('\n'))
}

exports.createHash = function (alg) {
  alg = alg || 'sha1'
  if(!algorithms[alg])
    error('algorithm:', alg, 'is not yet supported')
  var s = ''
  _alg = algorithms[alg]
  return {
    update: function (data) {
      s += data
      return this
    },
    digest: function (enc) {
      enc = enc || 'binary'
      var fn 
      if(!(fn = _alg[enc]))
        error('encoding:', enc , 'is not yet supported for algorithm', alg)
      var r = fn(s)
      s = null //not meant to use the hash after you've called digest.
      return r
    }
  }
}
// the least I can do is make error messages for the rest of the node.js/crypto api.
;['createCredentials'
, 'createHmac'
, 'createCypher'
, 'createCypheriv'
, 'createDecipher'
, 'createDecipheriv'
, 'createSign'
, 'createVerify'
, 'createDeffieHellman',
, 'pbkdf2',
, 'randomBytes' ].forEach(function (name) {
  exports[name] = function () {
    error('sorry,', name, 'is not implemented yet')
  }
})

});

require.define("/node_modules/crypto-browserify/sha.js", function (require, module, exports, __dirname, __filename) {
/*
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined
 * in FIPS PUB 180-1
 * Version 2.1a Copyright Paul Johnston 2000 - 2002.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for details.
 */

exports.hex_sha1 = hex_sha1;
exports.b64_sha1 = b64_sha1;
exports.str_sha1 = str_sha1;
exports.hex_hmac_sha1 = hex_hmac_sha1;
exports.b64_hmac_sha1 = b64_hmac_sha1;
exports.str_hmac_sha1 = str_hmac_sha1;

/*
 * Configurable variables. You may need to tweak these to be compatible with
 * the server-side, but the defaults work in most cases.
 */
var hexcase = 0;  /* hex output format. 0 - lowercase; 1 - uppercase        */
var b64pad  = ""; /* base-64 pad character. "=" for strict RFC compliance   */
var chrsz   = 8;  /* bits per input character. 8 - ASCII; 16 - Unicode      */

/*
 * These are the functions you'll usually want to call
 * They take string arguments and return either hex or base-64 encoded strings
 */
function hex_sha1(s){return binb2hex(core_sha1(str2binb(s),s.length * chrsz));}
function b64_sha1(s){return binb2b64(core_sha1(str2binb(s),s.length * chrsz));}
function str_sha1(s){return binb2str(core_sha1(str2binb(s),s.length * chrsz));}
function hex_hmac_sha1(key, data){ return binb2hex(core_hmac_sha1(key, data));}
function b64_hmac_sha1(key, data){ return binb2b64(core_hmac_sha1(key, data));}
function str_hmac_sha1(key, data){ return binb2str(core_hmac_sha1(key, data));}

/*
 * Perform a simple self-test to see if the VM is working
 */
function sha1_vm_test()
{
  return hex_sha1("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d";
}

/*
 * Calculate the SHA-1 of an array of big-endian words, and a bit length
 */
function core_sha1(x, len)
{
  /* append padding */
  x[len >> 5] |= 0x80 << (24 - len % 32);
  x[((len + 64 >> 9) << 4) + 15] = len;

  var w = Array(80);
  var a =  1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d =  271733878;
  var e = -1009589776;

  for(var i = 0; i < x.length; i += 16)
  {
    var olda = a;
    var oldb = b;
    var oldc = c;
    var oldd = d;
    var olde = e;

    for(var j = 0; j < 80; j++)
    {
      if(j < 16) w[j] = x[i + j];
      else w[j] = rol(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);
      var t = safe_add(safe_add(rol(a, 5), sha1_ft(j, b, c, d)),
                       safe_add(safe_add(e, w[j]), sha1_kt(j)));
      e = d;
      d = c;
      c = rol(b, 30);
      b = a;
      a = t;
    }

    a = safe_add(a, olda);
    b = safe_add(b, oldb);
    c = safe_add(c, oldc);
    d = safe_add(d, oldd);
    e = safe_add(e, olde);
  }
  return Array(a, b, c, d, e);

}

/*
 * Perform the appropriate triplet combination function for the current
 * iteration
 */
function sha1_ft(t, b, c, d)
{
  if(t < 20) return (b & c) | ((~b) & d);
  if(t < 40) return b ^ c ^ d;
  if(t < 60) return (b & c) | (b & d) | (c & d);
  return b ^ c ^ d;
}

/*
 * Determine the appropriate additive constant for the current iteration
 */
function sha1_kt(t)
{
  return (t < 20) ?  1518500249 : (t < 40) ?  1859775393 :
         (t < 60) ? -1894007588 : -899497514;
}

/*
 * Calculate the HMAC-SHA1 of a key and some data
 */
function core_hmac_sha1(key, data)
{
  var bkey = str2binb(key);
  if(bkey.length > 16) bkey = core_sha1(bkey, key.length * chrsz);

  var ipad = Array(16), opad = Array(16);
  for(var i = 0; i < 16; i++)
  {
    ipad[i] = bkey[i] ^ 0x36363636;
    opad[i] = bkey[i] ^ 0x5C5C5C5C;
  }

  var hash = core_sha1(ipad.concat(str2binb(data)), 512 + data.length * chrsz);
  return core_sha1(opad.concat(hash), 512 + 160);
}

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function safe_add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left.
 */
function rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt));
}

/*
 * Convert an 8-bit or 16-bit string to an array of big-endian words
 * In 8-bit function, characters >255 have their hi-byte silently ignored.
 */
function str2binb(str)
{
  var bin = Array();
  var mask = (1 << chrsz) - 1;
  for(var i = 0; i < str.length * chrsz; i += chrsz)
    bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (32 - chrsz - i%32);
  return bin;
}

/*
 * Convert an array of big-endian words to a string
 */
function binb2str(bin)
{
  var str = "";
  var mask = (1 << chrsz) - 1;
  for(var i = 0; i < bin.length * 32; i += chrsz)
    str += String.fromCharCode((bin[i>>5] >>> (32 - chrsz - i%32)) & mask);
  return str;
}

/*
 * Convert an array of big-endian words to a hex string.
 */
function binb2hex(binarray)
{
  var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
  var str = "";
  for(var i = 0; i < binarray.length * 4; i++)
  {
    str += hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8+4)) & 0xF) +
           hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8  )) & 0xF);
  }
  return str;
}

/*
 * Convert an array of big-endian words to a base-64 string
 */
function binb2b64(binarray)
{
  var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var str = "";
  for(var i = 0; i < binarray.length * 4; i += 3)
  {
    var triplet = (((binarray[i   >> 2] >> 8 * (3 -  i   %4)) & 0xFF) << 16)
                | (((binarray[i+1 >> 2] >> 8 * (3 - (i+1)%4)) & 0xFF) << 8 )
                |  ((binarray[i+2 >> 2] >> 8 * (3 - (i+2)%4)) & 0xFF);
    for(var j = 0; j < 4; j++)
    {
      if(i * 8 + j * 6 > binarray.length * 32) str += b64pad;
      else str += tab.charAt((triplet >> 6*(3-j)) & 0x3F);
    }
  }
  return str;
}


});

require.define("/lib/consts.js", function (require, module, exports, __dirname, __filename) {

exports.K = 8; /* bucket size */
exports.MAX_FAIL = 20;
exports.ALPHA = 3; /* parallel lookups */

});

require.define("/lib/rtable.js", function (require, module, exports, __dirname, __filename) {

var util = require('./util');
var consts = require('./consts');

function RTNode(address, port, id, failed_pings) {
	this.address = address.toString();
	this.port = port | 0;
	this.id = util.id_dup(id);
	this.failed_pings = failed_pings; // -1 means not pinged yet
}

function rtnode_eq(a, b) {
	return (a.address === b.address && a.port === b.port && util.id_eq(a, b));
}

function RouteEntry() {
	this.live = [];
	this.replacement = [];
	this.last_refresh = 160;
}

RouteEntry.prototype.split = function split(own_id, own_ndx) {
	var nbucket = new RouteEntry(), i, l;
	var old;

	old = this.live;
	this.live = [];
	for (i = 0, l = old.length; i < l; ++i) {
		if (util.id_common(own_id, old[i]) > own_ndx) {
			nbucket.live.push(old[i]);
		} else {
			this.live.push(old[i]);
		}
	}

	old = this.replacement;
	this.replacement = [];
	for (i = 0, l = old.length; i < l; ++i) {
		if (util.id_common(own_id, old[i]) > own_ndx) {
			if (nbucket.live.length < consts.K) {
				nbucket.live.push(old[i]);
			} else {
				nbucket.replacement.push(old[i]);
			}
		} else {
			if (this.live.length < consts.K) {
				this.live.push(old[i]);
			} else {
				this.replacement.push(old[i]);
			}
		}
	}

	nbucket.last_refresh = 160 - own_ndx - 1;

	return nbucket;
}

function RoutingTable(dht) {
	this.dht = dht;
	/* index is the length of the common prefix with this.dht.id; last bucket catches all remaining */
	this.table = [ new RouteEntry() ];
	this.last_refresh = 0;
	this.last_self_refresh = 0;
}

exports.RoutingTable = RoutingTable;

RoutingTable.prototype.start = function start() {
	this.refresh_id = setInterval(this._refresh.bind(this), 5000);
}

RoutingTable.prototype.stop = function stop() {
	clearInterval(this.refresh_id);
}

RoutingTable.prototype._refresh = function _refresh() {
	var i, min_ndx, min_time, t, bucket, now = util.time_now();
	if (now - this.last_self_refresh > 15*60) {
		this.last_self_refresh = now;
		this.dht._refresh(this.dht.id);
		return;
	}

	if (now - this.last_refresh < 15*60) return;

	min_ndx = -1;
	min_time = now + consts.K * 5;
	for (i in this.table) {
		bucket = this.table[i];
		t = bucket.last_refresh + bucket.live.length * 5;
		if (t < min_time) {
			t = min_time;
			min_ndx = i;
		}
	}

	if (-1 === min_ndx) return;

	bucket = this.table[min_ndx];
	if (now - bucket.last_refresh < 45) return;

	this.last_refresh = now;
	this.dht._refresh(util.id_random_with_prefix(this.dht.id, min_ndx));
}

RoutingTable.prototype._find_bucket = function find_bucket(id) {
	var ndx = util.id_common(this.dht.id, id);
	if (ndx >= this.table.length) ndx = this.table.length - 1;
	return ndx;
}

RoutingTable.prototype._add_node = function add_node(node) {
	var i, n, ndx, bucket, nbucket, can_split, max_fail_ndx, max_fail;

	if (util.id_eq(node.id, this.dht.id)) return;

	ndx = this._find_bucket(node.id);
	bucket = this.table[ndx];

	for (i in bucket.live) {
		n = bucket.live[i];
		if (util.id_eq(n.id, node.id)) {
			/* move to back, update */
			bucket.live.splice(i, 1);
			/* only update if old address failed and new node was pinged */
			bucket.live.push( (node.failed_pings === 0 && n.failed_pings !== 0) ? node : n );
			return;
		}
	}

	for (i in bucket.replacement) {
		n = bucket.replacement[i];
		if (util.id_eq(n.id, node.id)) {
			/* move to back, update */
			bucket.replacement.splice(i, 1);
			/* only update if old address failed and new node was pinged */
			bucket.replacement.push( (node.failed_pings === 0 && n.failed_pings !== 0) ? node : n );
			return;
		}
	}

	/* new node */
	if (bucket.live.length < consts.K) {
		bucket.live.push(node);
		return;
	}

	can_split = false;

	if (0 === node.failed_pings) {
		can_split = (ndx == this.table.length - 1) && (ndx < 159);

		max_fail_ndx = -1;
		max_fail = 0; /* higher fail limit before replacing a node? */
		for (i in bucket.live) {
			n = bucket.live[i];
			if (-1 === n.failed_pings) {
				/* replace unpinged n with node */
				bucket.live.splice(i, 1);
				bucket.live.push(node);
				return;
			} else if (n.failed_pings > max_fail) {
				max_fail_ndx = i;
				max_fail = n.failed_pings;
			}
		}

		if (-1 !== max_fail_ndx) {
			/* replace node that failed most with new node */
			bucket.live.splice(max_fail_ndx, 1);
			bucket.live.push(node);
			return;
		}
	}

	if (!can_split) {
		if (bucket.replacement.length >= consts.K) {
			max_fail_ndx = -1;
			max_fail = -1;
			for (i in bucket.replacement) {
				n = bucket.replacement[i];
				if (-1 === n.failed_pings) {
					/* replace unpinged n with node */
					bucket.replacement.splice(i, 1);
					bucket.replacement.push(node);
					return;
				} else if (n.failed_pings > max_fail) {
					max_fail_ndx = i;
					max_fail = n.failed_pings;
				}
			}

			/* only replace good nodes if the new node is good too */
			if (-1 !== max_fail_ndx && (max_fail > 0 || node.failed_pings === 0)) {
				bucket.replacement.splice(max_fail, 1);
				bucket.replacement.push(node);
				return;
			}
		} else {
			bucket.replacement.push(node);
		}

		return;
	}

	/* split */
	nbucket = bucket.split(this.dht.id, ndx);
	this.table.push(nbucket);

	/* try adding now */
	ndx = this._find_bucket(node.id);
	bucket = this.table[ndx];
	if (bucket.live.length < consts.K) {
		bucket.live.push(node);
	} else if (bucket.replacement.length < consts.K) {
		bucket.replacement.push(node);
	}
}

RoutingTable.prototype.node_seen = function node_seen(address, port, id) {
	this._add_node(new RTNode(address, port, id, 0));
}

RoutingTable.prototype.heard_about = function heard_about(node) {
	this._add_node(new RTNode(node.address, node.port, node.id, -1));
}

RoutingTable.prototype.node_failed = function node_failed(id) {
	var ndx, bucket, i, node;

	ndx = this._find_bucket(id);
	bucket = this.table[ndx];

	for (i in bucket.live) {
		node = bucket.live[i];
		if (util.id_eq(node.id, id)) {
			if (0 == bucket.replacement.length) {
				if (-1 === node.failed_pings || node.failed_pings+1 >= consts.MAX_FAIL) {
					/* remove node */
					bucket.live.splice(i, 1);
				}
				++node.failed_pings;
			} else {
				/* remove node */
				bucket.live.splice(i, 1);
				/* replace with "good" node */
				for (i in bucket.replacement) {
					node = bucket.replacement[i];
					if (0 === node.failed_pings) {
						bucket.replacement.splice(i, 1);
						bucket.live.push(node);
						return;
					}
				}
				/* or the first if no good node was found */
				bucket.live.push(bucket.replacement.shift());
			}
			return;
		}
	}
	/* was not a live node */

	for (i in bucket.replacement) {
		node = bucket.replacement[i];
		if (util.id_eq(node.id, id)) {
			/* remove node */
			bucket.replacement.splice(i, 1);
			return;
		}
	}
}

RoutingTable.prototype.lookup = function lookup(id, count, include_failed) {
	var ndx, bucket, i, node, r = [], rx, cmp;

	if (-1 === count) include_failed = true;

	cmp = util.compare_nodes_for(id);

	ndx = this._find_bucket(id);
	bucket = this.table[ndx];
	if (include_failed) {
		util.array_append(r, bucket.live.slice().sort(cmp));
	} else {
		util.array_append(r, bucket.live.filter(function (n) { return (0 === n.failed_pings); }).sort(cmp));
	}

	if (-1 === count || r.length < count) {
		i = ndx + 1;
		rx = [];
		while (i < this.table.length) {
			bucket = this.table[i];
			if (include_failed) {
				util.array_append(rx, bucket.live);
			} else {
				util.array_append(rx, bucket.live.filter(function (n) { return (0 === n.failed_pings); }));
			}
			++i;
		}
		rx.sort(cmp);
		util.array_append(r, rx);
	}

	if (-1 === count || r.length < count) {
		i = ndx -1 ;
		rx = [];
		while ((-1 === count || r.length < count) && i >= 0) {
			bucket = this.table[i];
			if (include_failed) {
				util.array_append(rx, bucket.live);
			} else {
				util.array_append(rx, bucket.live.filter(function (n) { return (0 === n.failed_pings); }));
			}
			--i;
		}
		rx.sort(cmp);
		util.array_append(r, rx);
	}

	if (count >= 0) r.splice(count);
	return r;
}

});

require.define("/lib/traverse.js", function (require, module, exports, __dirname, __filename) {

var util = require('./util');
var consts = require('./consts');

function traverse_get_peers(traversal, node, callback) {
	traversal.dht._get_peers(node.address, node.port, node.id, traversal.target, function(response) {
		var nodes, values, i, l, peer, token, peers;
		if (!response) return callback(); /* timeout */

		if (!traversal.peers) { traversal.peers = []; traversal.nodes = []; };

		token = response.r.token;
		if (!token || !(token instanceof Buffer)) return callback();

		util.accumulate_nodes(traversal.nodes, traversal.target, { 'address': node.address, 'port': node.port, 'id': node.id, 'token': token }, consts.K);

		values = response.r.values;
		peers = [];
		if (values && !Array.isArray(values)) return callback();
		if (values) {
			for (i = 0, l = values.length; i < l; ++i) {
				peer = util.decode_peer_info(values[i]);
				if (!peer) continue;
				traversal.peers.push(peer);
				peers.push(peer);
			}
		}
		if (traversal.peer_callback && peers.length > 0) traversal.peer_callback(peers);

		nodes = util.decode_node_info(response.r.nodes);
		callback(nodes);
	});
}

exports.traverse_get_peers = traverse_get_peers;


function traverse_refresh(traversal, node, callback) {
	if (node.id && util.id_eq(node.id, traversal.target)) {
		traversal.dht._ping(node.address, node.port, node.id, function(response) {
			if (!response) return callback(); /* timeout */

			traversal.done();
		});
	} else {
		traversal.dht._find_node(node.address, node.port, node.id, traversal.target, function(response) {
			var nodes;
			if (!response) return callback(); /* timeout */

			nodes = util.decode_node_info(response.r.nodes);
			if (null === nodes) {
				util.debug("Unexpected nodes value: ", nodes);
				return callback(); /* invalid/empty response */
			}

			callback(nodes);
		});
	}
}

exports.traverse_refresh = traverse_refresh;

function Traversal(dht, target, invokecb, callback) {
	this.dht = dht;
	this.target = target;
	this.invokecb = invokecb;
	this.max_requests = 2 * consts.K;
	this.pending = 0;
	this.seen = { };
	this.queue = [ ];
	this.callback = callback;
	this.finished = false;
}

exports.Traversal = Traversal;

Traversal.prototype.start = function start() {
	if (0 === this.queue.length) {
		this.add_list(this.dht.rtable.lookup(this.target, consts.K, false));
	}

	if (0 === this.queue.length) {
		util.debug("Cannot connect to DHT without any known nodes");
		this.callback(new Error("Cannot connect to DHT without any known nodes"));
	}

	this.run();
}

Traversal.prototype.run = function run() {
	var n;

	while (!this.finished && this.max_requests != 0 && this.pending < consts.ALPHA && this.queue.length > 0) {
		n = this.queue.shift();
		++this.pending;
		if (this.max_requests > 0) --this.max_requests;
		this.invokecb(this, n, util.short_timeout(2000, function (shortmode, newnodes) {
			if (this.finished) return;

			if (shortmode !== 2) {
				--this.pending;
			}

			if (newnodes) {
				newnodes.forEach(this.add.bind(this));
				newnodes.forEach(this.dht.rtable.heard_about.bind(this.dht.rtable));
			}

			if (this.abort_id) {
				clearTimeout(this.abort_id);
				delete this.abort_id;
			}

			this.run();
		}.bind(this)));
	}

	if (this.finished) return;

	if ((0 === this.max_requests || 0 === this.queue.length) && 0 === this.pending) {
		this.abort_id = setTimeout(this.done.bind(this), 5000);
	}
}

Traversal.prototype.done = function done() {
	if (this.finished) return;

	if (this.abort_id) {
		clearTimeout(this.abort_id);
		delete this.abort_id;
	}

	this.finished = true;

	this.callback.apply(null, arguments);
}

/* object nodes with: .address, .port and optional .id */
Traversal.prototype.add = function add(node) {
	var i, k, c;

	k = node.address + '/' + node.key;
	if (this.seen[k]) return;
	this.seen[k] = true;

	if (!node.id) {
		this.queue.push(node);
		return;
	}

	util.accumulate_nodes(this.queue, this.target, node);
}

/* list is assumed to be "sorted" - otherwise use nodes.forEach(traversal.add.bind(traversal)); */
Traversal.prototype.add_list = function add_list(nodes) {
	var i, n, k;

	for (i in nodes) {
		n = nodes[i];
		k = n.address + '/' + n.port;
		if (this.seen[k]) continue;

		this.seen[k] = true;
		this.queue.push(n);
	}
}

});

require.define("/lib/rpc.js", function (require, module, exports, __dirname, __filename) {

var util = require('./util');
var consts = require('./consts');

function Query(dht, address, port, message) {
	this.dht = dht;
	this.address = address;
	this.port = port;
	this.tid = message.t;
	this.done = false;
}

exports.Query = Query;

Query.prototype.respond = function respond(msg) {
	if (this.done) return false;
	this.done = true;
	msg.t = this.tid;
	msg.y = 'r';
	if (undefined === msg.r) msg.r = {};
	msg.r.id = this.dht.id;
	this.dht._send(this.address, this.port, msg);
	return true;
}

Query.prototype.error = function error(code, message) {
	if (this.done) return false;
	this.done = true;
	if (!message) {
		switch (code) {
		case 201: message = 'Generic Error'; break;
		case 202: message = 'Server Error'; break;
		case 203: message = 'Protocol Error'; break;
		case 204: message = 'Method Unknown'; break;
		}
	}
	var msg = { };
	msg.t = this.tid;
	msg.y = 'e';
	msg.e = [code, message];
	this.dht._send(this.address, this.port, msg);
	return true;
}

Query.prototype.getToken = function getToken() {
	this.dht.getToken(this.address, this.port);
}
Query.prototype.verifyToken = function verifyToken(token) {
	this.dht.verifyToken(this.address, this.port, token);
}

Query.prototype.handle = function handle(data) {
	var qtype, qhandler, node;
	qtype = data.q;
	if (!qtype || !(qtype instanceof Buffer)) return this.error(203);
	data.q = qtype = qtype.toString('ascii');
	qhandler = query_types[qtype];
	if (!qhandler) return this.error(204);
	qhandler(this, data);
}

function transaction_timeout(transaction) {
	delete transaction.node.transactions[transaction.tid];
	transaction.node.failed();
	transaction.callback(null, transaction.node);
	transaction.node.unqueue();
}

function Transaction(node, tid, message, callback) {
	if (!callback) throw new Error('');
	this.node = node;
	this.tid = tid;
	this.callback = callback;
	this.timeoutID = setTimeout(transaction_timeout, 10000, this);

	message.t = util.tid_to_buffer(tid);
	message.y = "q";
	if (!message.a) message.a = {};
	message.a.id = node.dht.id;
	node.send(message);
}

Transaction.prototype.response = function response(message) {
	var r, id;

	if ("r" === message.y) {
		r = message.r;
		if (!r || !(r instanceof Object)) return this.node.failed();
		/* check id presence */
		id = r.id;
		if (!id || !(id instanceof Buffer) || id.length != 20) return this.node.failed();
		/* unexpected id */
		if (this.node.id && !util.id_eq(this.node.id, id)) return this.node.failed();
		this.node.id = id;
	}

	clearTimeout(this.timeoutID);
	delete this.node.transactions[this.tid];

	if (this.node.id) this.node.seen();
	this.callback(message, this.node);
	this.node.unqueue();
}

function Node(dht, address, port, id) {
	this.dht = dht;
	this.address = address;
	this.port = port;
	this.id = id; /* maybe undefined */
	this.key = address + "/" + port;
	this.transactions = {};
	this.queue = [];
}
exports.Node = Node;

Node.prototype.find_transaction = function find_transaction(response) {
	var tid;
	if (!response.t || !(response.t instanceof Buffer)) return null;
	tid = util.buffer_to_tid(response.t);
	if (-1 == tid) return null;
	var t = this.transactions[tid];
	if (!t) return null;
	return t;
}

Node.prototype.send = function send(message) {
	this.dht._send(this.address, this.port, message);
}

Node.prototype.recv = function recv(message) {
	var trans;
	var id;

	switch (message.y) {
	case "q":
		if (!message.q || !(message.q instanceof Buffer)) return null;
		message.q = message.q.toString('ascii');

		if (!message.a || typeof message.a != 'object') return null;
		id = message.a.id;
		if (!id || !(id instanceof Buffer)) return null;
		break;
	case "r":
		trans = this.find_transaction(message);
		if (trans) trans.response(message);
		break;
	case "e":
		trans = this.find_transaction(message);
		if (trans) trans.response(message);
		break;
	default: return; /* invalid */
	}
}

Node.prototype.query = function query(message, callback) {
	if (Object.keys(this.transactions).length >= 5) return this.queue.push([message, callback]);

	if (Object.keys(this.transactions).length == 0) {
		this.dht.active_nodes[this.key] = this;
	}

	var tid;
	do {
		tid = util.generate_tid();
	} while (this.transactions[tid]);

	this.transactions[tid] = new Transaction(this, tid, message, callback);
}

Node.prototype.unqueue = function unqueue() {
	while (Object.keys(this.transactions).length < 5 && this.queue.length > 0) {
		var x = this.queue.shift();
		this.query(x[0], x[1]);
	}

	if (Object.keys(this.transactions).length == 0) {
		delete this.dht.active_nodes[this.key];
		delete this.dht.active_nodes[this.key];
	}
}

Node.prototype.seen = function seen() {
	if (this.id) this.dht.rtable.node_seen(this.address, this.port, this.id)
}

Node.prototype.failed = function failed() {
	if (this.id) this.dht.rtable.node_failed(this.id)
}

function query_ping(query, message) {
	query.respond({});
}

function query_find_node(query, message) {
	var target = message.a.target;
	if (!target || !(target instanceof Buffer) || target.length != 20) return query.error(203);
	nodes = query.dht.rtable.lookup(target, consts.K, false);
	query.respond({ 'r': { 'nodes' : util.encode_node_info(nodes) } });
}

function query_get_peers(query, message) {
	var info_hash = message.a.info_hash;
	if (!info_hash || !(info_hash instanceof Buffer) || info_hash.length != 20) return query.error(203);
	nodes = query.dht.rtable.lookup(info_hash, consts.K, false);
	values = query.dht.cache.get(info_hash);
	msg = { 'r': { 'token': query.getToken(), 'nodes' : util.encode_node_info(nodes) } };
	if (values.length > 0) msg.r.values = values.forEach(util.encode_peer_info);
	query.respond(msg);
}

function query_announce_peer(query, message) {
	var info_hash = message.a.info_hash;
	if (!info_hash || !(info_hash instanceof Buffer) || info_hash.length != 20) return query.error(203);
	var port = message.a.port;
	if (!port || typeof port != 'number' || port <= 0 || port > 65535) return query.error(203);
	var token = message.a.token;
	if (!token || !(token instanceof Buffer)) return query.error(203);
	if (!query.verifyToken(token)) return query.error(203, "Invalid Token");
	query.dht.rtable.node_seen(query.port, query.address, query.a.id);

	query.dht.cache.add(info_hash, { 'address': query.address, 'port': port });
	query.respond();
}

var query_types = {
	'ping': query_ping,
	'find_node': query_find_node,
	'get_peers': query_get_peers,
	'announce_peer': query_announce_peer,
};


});

require.define("/lib/cache.js", function (require, module, exports, __dirname, __filename) {

function Cache() {
	this.store = {};
}

exports.Cache = Cache;

Cache.prototype.start = function start() {
}

Cache.prototype.stop = function stop() {
}

Cache.prototype.get = function get(key) {
	return [];
}

Cache.prototype.add = function add(key, value) {
}

});

require.define("/node_modules/dht-bencode/package.json", function (require, module, exports, __dirname, __filename) {
module.exports = {"main":"./lib/bencode"}
});

require.define("/node_modules/dht-bencode/lib/bencode.js", function (require, module, exports, __dirname, __filename) {
/* http://natsuki.weeaboo.se:8080/~valderman/files/bencode.js */
/* Copyright (c) 2009 Anton Ekblad

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software. */

/* modified by Stefan Buehler to use node.js Buffers (c) 2010 */

if (!Buffer.prototype.charAt) Buffer.prototype.charAt = function charAt(i) {
	return String.fromCharCode(this[i]);
};

// bencode an object
function bencode(obj) {
	switch(btypeof(obj)) {
		case "string":     return bstring(obj);
		case "number":     return bint(obj);
		case "list":       return blist(obj);
		case "dictionary": return bdict(obj);
		default:           throw new Error('cannot encode element ' + obj);
	}
}

exports.bencode = bencode;

// decode a bencoded string into a javascript object
function bdecode(str) {
	if (!(str instanceof Buffer)) {
		str = new Buffer(str);
	}
	var dec = bparse(str, 0);
	if(dec !== null && dec[1] === str.length)
		return dec[0];
	throw new Error("couldn't decode data");
}

exports.bdecode = bdecode;

// parse a bencoded string; bdecode is really just a wrapper for this one.
// all bparse* functions return an array in the form
// [parsed object, remaining string to parse]
function bparse(str, pos) {
	switch(str.charAt(pos)) {
		case "d": return bparseDict(str, pos+1);
		case "l": return bparseList(str, pos+1);
		case "i": return bparseInt(str, pos+1);
		default:  return bparseString(str, pos);
	}
}

function findchar(str, pos, c) {
	while (pos < str.length) {
		if (str.charAt(pos) === c) return pos;
		++pos;
	}
	return -1;
}

function copy(str, start, len) {
	return str.slice(start, start+len);
// 	var buf = new Buffer(len);
// 	str.copy(buf, 0, start, start+len);
// 	return buf;
}

// parse a bencoded string
function bparseString(str, pos) {
	var colon, str2, len;
	colon = findchar(str, pos, ':');
	if (-1 === colon) throw new Error("couldn't find colon");
	str2 = str.toString('ascii', pos, colon);
	if(isNum(str2)) {
		len = parseInt(str2);
		return [ copy(str, colon+1, len), colon+1+len ];
	}
	throw new Error("string length is not numeric");
}

// parse a bencoded integer
function bparseInt(str, pos) {
	var end = findchar(str, pos, 'e');
	if (-1 === end) throw new Error("couldn't find end of int");
	var str2 = str.toString('ascii', pos, end);
	if(!isNum(str2))
		throw new Error("number contains non-digits");
	return [Number(str2), end+1];
}

// parse a bencoded list
function bparseList(str, pos) {
	var p, list = [];
	while (pos < str.length && str.charAt(pos) !== "e") {
		p = bparse(str, pos);
		if (null === p) throw new Error("unexpected null element");
		list.push(p[0]);
		pos = p[1];
	}
	if (pos >= str.length) throw new Error("unexpected end of data");
	return [list, pos+1];
}

// parse a bencoded dictionary
function bparseDict(str, pos) {
	var key, val, dict = {};
	while (pos < str.length && str.charAt(pos) !== "e") {
		key = bparseString(str, pos);
		if (null === key) throw new Error("unexpected null element");
		pos = key[1];
		if (pos >= str.length) throw new Error("unexpected end of data");

		val = bparse(str, pos);
		if (null === val) throw new Error("unexpected null element");

		dict[key[0]] = val[0];
		pos = val[1];
	}
	if (pos >= str.length) throw new Error("unexpected end of data");
	return [dict, pos+1];
}

// is the given string numeric?
function isNum(str) {
	var i, c;
	str = str.toString();
	if(str.charAt(0) === '-') {
		i = 1;
	} else {
		i = 0;
	}

	for(; i < str.length; ++i) {
		c = str.charCodeAt(i);
		if (c < 48 || c > 57) {
			return false;
		}
	}
	return true;
}

// returns the bencoding type of the given object
function btypeof(obj) {
	var type = typeof obj;
	if (null === obj) return "null";
	if (type === "object") {
		if (obj instanceof Buffer) return "string";
		if (obj instanceof Array) return "list";
		return "dictionary";
	}
	return type;
}

// bencode a string
function bstring(str) {
	if (str instanceof Buffer) {
		var len = str.length;
		var slen = len.toString() + ":";
		var buf = new Buffer(slen.length + len);
		buf.write(slen, 0, 'utf8');
		str.copy(buf, slen.length, 0, len);
		return buf;
	} else {
		var len = Buffer.byteLength(str, 'utf8');
		var slen = len.toString() + ":";
		var buf = new Buffer(slen.length + len);
		buf.write(slen, 0, 'utf8');
		buf.write(str, slen.length, 'utf8');
		return buf;
	}
}

// bencode an integer
function bint(num) {
	return new Buffer("i" + num + "e", 'utf8');
}

// bencode a list
function blist(list) {
	var enclist, i, l, buflen, b, buf, pos;

	enclist = [];
	buflen = 2;

	for (i = 0, l = list.length; i < l; ++i) {
		b = bencode(list[i]);
		enclist.push(b);
		buflen += b.length;
	}

	buf = new Buffer(buflen);
	buf.write('l', 0, 'ascii');
	pos = 1;

	for (i = 0, l = enclist.length; i < l; ++i) {
		b = enclist[i];
		b.copy(buf, pos, 0, b.length);
		pos += b.length;
	}
	buf.write('e', pos, 'ascii');
	return buf;
}

// bencode a dictionary
function bdict(dict) {
	var enclist, i, l, buflen, b, buf, pos, key, keylist;

	enclist = [];
	buflen = 2;

	keylist = Object.keys(dict).sort();

	for (i = 0, l = keylist.length; i < l; ++i) {
		key = keylist[i];
		if (!dict.hasOwnProperty(key)) continue;

		b = bstring(key);
		enclist.push(b);
		buflen += b.length;

		b = bencode(dict[key]);
		enclist.push(b);
		buflen += b.length;
	}

	buf = new Buffer(buflen);
	buf.write('d', 0, 'ascii');
	pos = 1;

	for (i = 0, l = enclist.length; i < l; ++i) {
		b = enclist[i];
		b.copy(buf, pos, 0, b.length);
		pos += b.length;
	}
	buf.write('e', pos, 'ascii');
	return buf;
}

});

require.define("/example.js", function (require, module, exports, __dirname, __filename) {
    var DHT = require('./lib/dht');
var dht = new DHT.DHT(51414);

// DHT.debug = true;

// for bootstrapping you need to know a node which already is in the dht
dht.start();
dht.bootstrap([ { 'address': 'xxx.xxx.xxx.xxx', 'port': xxx } ]);

var id = DHT.util.hex2buf("640FE84C613C17F663551D218689A64E8AEBEABE");

dht.lookup(id, function (peers, finished) {
	console.log("Found more peers: undefined", peers);
	if (finished) console.log("Lookup done");
});

});
require("/example.js");

