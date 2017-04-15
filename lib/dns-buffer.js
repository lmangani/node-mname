/*
 * Copyright (c) 2015 Trevor Orsztynowicz
 * Copyright (c) 2015 Joyent, Inc
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

module.exports = DNSBuffer;

var assert = require('assert-plus');

function DNSBuffer(opts) {
        assert.object(opts, 'options');
        assert.optionalBuffer(opts.buffer, 'options.buffer');

        this._size = opts.buffer ? opts.buffer.length : 1024;
        this._buffer = opts.buffer || (new Buffer(this._size));
        this._offset = 0;
        this._ncache = new NameOffsetCache();
}

DNSBuffer.prototype.toBuffer = function () {
        return (this._buffer.slice(0, this._offset));
};

DNSBuffer.prototype.atEnd = function () {
        return (this._offset >= this._size);
};

DNSBuffer.prototype.remainder = function () {
        return (this._buffer.slice(this._offset, this._size));
};

DNSBuffer.prototype.skip = function (n) {
        this._offset += n;
};

DNSBuffer.prototype.expand = function () {
        this._size *= 2;
        var buf = new Buffer(this._size);
        this._buffer.copy(buf, 0);
        this._buffer = buf;
};

DNSBuffer.prototype.read = function (bytes) {
        var v = this._buffer.slice(this._offset, this._offset + bytes);
        this._offset += bytes;
        return (v);
};

DNSBuffer.prototype.readUInt32 = function () {
        var v = this._buffer.readUInt32BE(this._offset);
        this._offset += 4;
        return (v);
};

DNSBuffer.prototype.readUInt16 = function () {
        var v = this._buffer.readUInt16BE(this._offset);
        this._offset += 2;
        return (v);
};

DNSBuffer.prototype.readUInt8 = function () {
        var v = this._buffer.readUInt8(this._offset++);
        return (v);
};

var NAME_META_MASK = 0xC0;
var NAME_STRING = 0x00;
var NAME_PTR = 0xC0;
var NAME_NAPTR = 0x23;

DNSBuffer.prototype.readName = function () {
        var rlen, name = '';

        var off = this._offset;
        var finalOff;

        rlen = this._buffer.readUInt8(off++);
        while (rlen !== 0x00 && name.length < 256) {
                var meta = rlen & NAME_META_MASK;

                if (meta == NAME_STRING) {
                        assert.ok(off + rlen < this._size,
                            'invalid name label length');
                        var buf = this._buffer.slice(off,
                            off + rlen);
                        off += rlen;
                        name += buf.toString('ascii') + '.';

                } else if (meta == NAME_PTR) {
                        var ptr = this._buffer.readUInt8(off++);
                        ptr = ptr | ((rlen & ~(0xC0)) << 8);

                        assert.ok(ptr < this._size,
                            'Invalid label pointer (off end of buffer)');
                        assert.ok(!(ptr >= this._offset && ptr <= off),
                            'Invalid label pointer (causes a loop)');

                        if (finalOff === undefined)
                                finalOff = off;
                        off = ptr;

                } else {
                        throw (new Error('Invalid name segment type: ' + meta));
                }

                rlen = this._buffer.readUInt8(off++);
        }

        if (name.length > 255) {
                throw (new Error('Invalid name (maximum length exceeded)'));
        }

        if (finalOff === undefined)
                finalOff = off;
        this._offset = finalOff;

        if (name.charAt(name.length - 1) === '.')
                name = name.slice(0, name.length - 1);

        return (name);
};

DNSBuffer.prototype.writeName = function (name) {
        assert.string(name, 'name');

        if (name === '' || name === '.') {
                this.writeUInt8(0);
                return;
        }
        if (name.charAt(name.length - 1) === '.')
                name = name.slice(0, name.length - 1);
        var maxIdx = name.length;

        var suffix = this._ncache.getSuffix(name);
        if (suffix.index !== undefined) {
                maxIdx = suffix.index;
        }

        var rlen;
        var i = -1, j;
        while (i < maxIdx) {
                var rem = name.slice(i + 1);
                j = name.indexOf('.', i + 1);
                if (j === -1)
                        j = name.length;
                var part = name.slice(i + 1, j);
                i = j;
                rlen = part.length;

                if (rlen === 0)
                        break;

                /* Can only use ptrs to things in the first 0x3fff bytes. */
                if (this._offset <= 0x3fff)
                        this._ncache.add(rem, this._offset);

                assert.ok(rlen < 64, 'segment "' + part + '" of name "' +
                    name + '" is too long');
                this.writeUInt8(rlen);
                this.write(new Buffer(part, 'ascii'));
        }

        if (suffix.offset !== undefined) {
                assert.ok(suffix.offset <= 0x3fff);

                var ptr = suffix.offset & 0xff;
                rlen = NAME_PTR | ((suffix.offset & 0x3f00) >> 8);
                this.writeUInt8(rlen);
                this.writeUInt8(ptr);

        } else {
                this.writeUInt8(0);
        }
};

DNSBuffer.prototype.writeNamePlain = function (name) {
        assert.string(name, 'name');

        if (name === '' || name === '.') {
                this.writeUInt8(0);
                return;
        }
        var rparts = name.split('.');

        var rlen;
        while (rparts.length > 0) {
                var part = rparts.shift();
                rlen = part.length;
                assert.ok(rlen < 64, 'segment "' + part + '" of name "' +
                    name + '" is too long');
                this.writeUInt8(rlen);
                this.write(new Buffer(part, 'ascii'));
        }
        this.writeUInt8(0);
};

DNSBuffer.prototype.writeUInt32 = function (v) {
        while (this._offset + 4 > this._size)
                this.expand();
        this._buffer.writeUInt32BE(v, this._offset);
        this._offset += 4;
};

DNSBuffer.prototype.writeUInt16 = function (v) {
        while (this._offset + 2 > this._size)
                this.expand();
        this._buffer.writeUInt16BE(v, this._offset);
        this._offset += 2;
};

DNSBuffer.prototype.writeUInt8 = function (v) {
        while (this._offset + 1 > this._size)
                this.expand();
        this._buffer.writeUInt8(v, this._offset++);
};

DNSBuffer.prototype.write = function (buf) {
        while (this._offset + buf.length > this._size)
                this.expand();
        buf.copy(this._buffer, this._offset);
        this._offset += buf.length;
};

/* node 0.10 and earlier do not have read/writeUIntBE on Buffers */
if (Buffer.prototype.readUIntBE !== undefined &&
        Buffer.prototype.writeUIntBE !== undefined) {

        DNSBuffer.prototype.readLengthPrefixed = function (lenBytes, cb) {
                var len = this._buffer.readUIntBE(this._offset, lenBytes);
                this._offset += lenBytes;

                var child = Object.create(this);
                child._size = this._offset + len;
                var ret = cb(child);
                this._offset += len;

                return (ret);
        };

        DNSBuffer.prototype.writeLengthPrefixed = function (lenBytes, cb) {
                var lenOffset = this._offset;
                this._offset += lenBytes;
                var ret = cb(this);
                var len = this._offset - lenOffset - lenBytes;
                this._buffer.writeUIntBE(len, lenOffset, lenBytes);

                return (ret);
        };

} else {

        DNSBuffer.prototype.readLengthPrefixed = function (lenBytes, cb) {
                var len;
                switch (lenBytes) {
                case 1:
                        len = this._buffer.readUInt8(this._offset);
                        break;
                case 2:
                        len = this._buffer.readUInt16BE(this._offset);
                        break;
                case 4:
                        len = this._buffer.readUInt32BE(this._offset);
                        break;
                default:
                        throw (new Error('Invalid prefix length value'));
                }
                this._offset += lenBytes;

                var child = Object.create(this);
                child._size = this._offset + len;
                var ret = cb(child);
                this._offset += len;

                return (ret);
        };

        DNSBuffer.prototype.writeLengthPrefixed = function (lenBytes, cb) {
                assert.ok(lenBytes === 1 || lenBytes === 2 || lenBytes === 4);

                var lenOffset = this._offset;
                this._offset += lenBytes;
                var ret = cb(this);
                var len = this._offset - lenOffset - lenBytes;
                switch (lenBytes) {
                case 1:
                        this._buffer.writeUInt8(len, lenOffset);
                        break;
                case 2:
                        this._buffer.writeUInt16BE(len, lenOffset);
                        break;
                case 4:
                        this._buffer.writeUInt32BE(len, lenOffset);
                        break;
                default:
                        throw (new Error('Invalid prefix length value'));
                }

                return (ret);
        };

}

/*
 * We are expected to run on node v0.10, which lacks Map. Polyfill just the
 * bits of it we actually need here. Map is a bit faster than an object for our
 * task, but an object will do as a substitute on 0.10.
 */
if (typeof (Map) !== 'function') {
        var Map = function () {
                this._obj = Object.create(null);
        };
        Map.prototype.set = function (k, v) {
                this._obj[k] = v;
        };
        Map.prototype.get = function (k) {
                return (this._obj[k]);
        };
}

function NameOffsetCache() {
        this.root = new Map();
}

NameOffsetCache.prototype.add = function (name, offset) {
        this.root.set(name, offset);
};

NameOffsetCache.prototype.getSuffix = function (name) {
        var i = -1;
        while (i < name.length) {
                var off = this.root.get(name.slice(i + 1));
                if (off !== undefined) {
                        return ({
                                index: i,
                                offset: off
                        });
                }
                if ((i = name.indexOf('.', i + 1)) === -1)
                        break;
        }
        return ({});
};
