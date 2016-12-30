export class BufferWriter {
  constructor(capacity = 256) {
    this._buffer = Buffer.alloc(256);
    this._length = 0;
  }

  _ensureCapacity(diff) {
    let newLength = this._length + diff;
    if (this._buffer.length >= diff) return;
    let newCapacity = Math.max(newLength, this._buffer.length * 2);
    this._buffer = Buffer.concat([this._buffer], newCapacity);
  }

  writeUInt8(value) {
    this._ensureCapacity(1);
    this._buffer.writeUInt8(value, this._length);
    this._length += 1;
    return this;
  }

  writeUInt16BE(value) {
    this._ensureCapacity(2);
    this._buffer.writeUInt16BE(value, this._length);
    this._length += 2;
    return this;
  }

  writeInt32BE(value) {
    this._ensureCapacity(4);
    this._buffer.writeInt32BE(value, this._length);
    this._length += 4;
    return this;
  }

  writeUInt32BE(value) {
    this._ensureCapacity(4);
    this._buffer.writeUInt32BE(value, this._length);
    this._length += 4;
    return this;
  }

  writeBuffer(buffer) {
    this._ensureCapacity(buffer.length);
    buffer.copy(this._buffer, this._length);
    this._length += buffer.length;
    return this;
  }

  writeString(string, encoding = 'utf-8') {
    this.writeBuffer(Buffer.from(string, encoding));
    return this;
  }

  getBuffer() {
    return this._buffer.slice(0, this._length);
  }
}

export class BufferReader {
  constructor(buffer) {
    this._buffer = buffer;
    this._ptr = 0;
  }

  _boundCheck(diff) {
    if (this._ptr + diff > this._buffer.length) throw new RangeError('Index out of bounds');
  }

  readUInt8() {
    this._boundCheck(1);
    let ret = this._buffer.readUInt8(this._ptr);
    this._ptr += 1;
    return ret;
  }

  readUInt16BE() {
    this._boundCheck(2);
    let ret = this._buffer.readUInt16BE(this._ptr);
    this._ptr += 2;
    return ret;
  }

  readInt32BE() {
    this._boundCheck(4);
    let ret = this._buffer.readInt32BE(this._ptr);
    this._ptr += 4;
    return ret;
  }

  readUInt32BE() {
    this._boundCheck(4);
    let ret = this._buffer.readUInt32BE(this._ptr);
    this._ptr += 4;
    return ret;
  }

  readBuffer(length) {
    this._boundCheck(length);
    let buffer = this._buffer.slice(this._ptr, this._ptr + length);
    this._ptr += length;
    return buffer;
  }

  readString(length, encoding = 'utf-8') {
    return this.readBuffer(length).toString(encoding);
  }

}

