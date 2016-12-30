import {BufferReader, BufferWriter} from './buffer';

class DNSBufferReader extends BufferReader {
  constructor(...args) {
    super(...args);
  }

  readName() {
    let ret = [];
    while (true) {
      let segLen = this.readUInt8();
      if (segLen === 0) return ret.join('.');
      if ((segLen & 0xC0) === 0) {
        // Uncompressed label
        ret.push(this.readString(segLen));
      } else if((segLen & 0xC0) === 0xC0) {
        // Compressed label
        // Read the other octat and get the offset
        let offset = ((segLen &~ 0xC0) << 8) | this.readUInt8();
        // Backup current offsett and read the name
        let ptrBackup = this._ptr;
        this._ptr = offset;
        ret.push(this.readName());
        this._ptr = ptrBackup;
        // Join up parsed labels and the pointer
        return ret.join('.');
      } else {
        throw new Error('Cannot parse DNS packet');
      }
    }
  }
}

class DNSBufferWriter extends BufferWriter {
  constructor(...args) {
    super(...args);

    this._names = Object.create(null);
  }

  writeName(name) {
    if (name in this._names) {
      this.writeUInt16BE(this._names[name] | 0xC000);
    } else {
      let id = name.indexOf('.');
      if (id === -1) {
        this.writeUInt8(name.length);
        this.writeString(name);
        this.writeUInt8(0);
      } else {
        let ptr = this._length;
        this.writeUInt8(id);
        this.writeString(name.substr(0, id));
        this.writeName(name.substr(id + 1));
        this._names[name] = ptr;
      }
    }
    return this;
  }
}

class DNSQuestion {
  constructor() {
    this.qname = '';
    this.qtype = 0;
    this.qclass = 0;
  }

  _serialize(writer) {
    writer
      .writeName(this.qname)
      .writeUInt16BE(this.qtype)
      .writeUInt16BE(this.qclass);
  }

  static _deserialize(reader) {
    let q = new DNSQuestion();
    q.qname = reader.readName();
    q.qtype = reader.readUInt16BE();
    q.qclass = reader.readUInt16BE();
    return q;
  }
}

class DNSRecord {
  constructor() {
    this.name = '';
    this.type = 0;
    this.class = 1;
    this.ttl = 0;
  }

  _serialize(writer) {
    writer
      .writeName(this.name)
      .writeUInt16BE(this.type)
      .writeUInt16BE(this.class)
      .writeInt32BE(this.ttl);
    let ptr = writer._length;
    writer._length += 2;
    this._serializeData(writer);
    let newptr = writer._length;
    let len = newptr - ptr - 2;
    writer._length = ptr;
    writer.writeUInt16BE(len);
    writer._length = newptr;
  }

  _serializeData(writer) {
    writer.writeBuffer(this.rdata);
  }

  _deserializeData(reader, rdlength) {
    this.rdata = reader.readBuffer(rdlength);
  }

  static _deserialize(reader) {
    let name = reader.readName();
    let type = reader.readUInt16BE();
    let ctor = type in DNSRecord._registry ? DNSRecord._registry[type] : DNSRecord;
    let rec = new ctor();
    rec.name = name;
    rec.type = type;
    rec.class = reader.readUInt16BE();
    rec.ttl = reader.readInt32BE();

    // Per RFC 2181, negative TTL are treated as zero
    if (rec.ttl < 0) rec.ttl = 0;

    let rdlength = reader.readUInt16BE();
    rec._deserializeData(reader, rdlength);
    return rec;
  }
}

DNSRecord._registry = [];

class DNSPacket {
  constructor() {
    this.id = 0;
    this.isResponse = false;
    this.opcode = 0;
    this.authoritative = false;
    this.truncation = false;
    this.recursionDesired = false;
    this.recursionAvailable = false;
    this.responseCode = 0;
    this.questions = [];
    this.answers = [];
    this.authorities = [];
    this.additionals = [];
  }

  static _deserialize(reader) {
    let packet = new DNSPacket();
    // Decode header
    packet.id = reader.readUInt16BE();
    let flags = reader.readUInt16BE();
    packet.isResponse = (flags & 0x8000) !== 0;
    packet.opcode = (flags >> 11) & 0xF;
    packet.authoritative = (flags & 0x0400) !== 0;
    packet.truncation = (flags & 0x0200) !== 0;
    packet.recursionDesired = (flags & 0x0100) !== 0;
    packet.recursionAvailable = (flags & 0x0080) !== 0;
    packet.responseCode = flags & 0xF;
    packet.questions = new Array(reader.readUInt16BE());
    packet.answers = new Array(reader.readUInt16BE());
    packet.authorities = new Array(reader.readUInt16BE());
    packet.additionals = new Array(reader.readUInt16BE());
    // Decode questions
    for (let i = 0; i < packet.questions.length; i++) {
      packet.questions[i] = DNSQuestion._deserialize(reader);
    }

    for (let i = 0; i < packet.answers.length; i++) {
      packet.answers[i] = DNSRecord._deserialize(reader);
    }
    
    for (let i = 0; i < packet.authorities.length; i++) {
      packet.authorities[i] = DNSRecord._deserialize(reader);
    }

    for (let i = 0; i < packet.additionals.length; i++) {
      packet.additionals[i] = DNSRecord._deserialize(reader);
    }
    return packet;
  }

  static fromBuffer(buffer) {
    let reader = new DNSBufferReader(buffer);
    return DNSPacket._deserialize(reader);
  }

  _serialize(writer) {
    // ID
    writer.writeUInt16BE(this.id);
    // Flags
    let flags = 0;
    if (this.isResponse) flags |= 0x8000;
    flags |= this.opcode << 11;
    if (this.authoritative) flags |= 0x0400;
    if (this.truncation) flags |= 0x0200;
    if (this.recursionDesired) flags |= 0x0100;
    if (this.recursionAvailable) flags |= 0x0080;
    flags |= this.responseCode;
    writer
      .writeUInt16BE(flags)
      .writeUInt16BE(this.questions.length)
      .writeUInt16BE(this.answers.length)
      .writeUInt16BE(this.authorities.length)
      .writeUInt16BE(this.additionals.length);
    // Now we finished header construction
    for (let question of this.questions) {
      question._serialize(writer);
    }
    // Records
    for (let rec of this.answers) {
      rec._serialize(writer);
    }
    for (let rec of this.authorities) {
      rec._serialize(writer);
    }
    for (let rec of this.additionals) {
      rec._serialize(writer);
    }
    return writer.getBuffer();
  }

  toBuffer() {
    let writer = new DNSBufferWriter();
    this._serialize(writer);
    return writer.getBuffer();
  }
}

export {DNSQuestion, DNSRecord, DNSPacket};
