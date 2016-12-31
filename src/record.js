import {DNSRecord} from './packet';
import * as DNSRecordType from './type';
import {IPv4, IPv6} from './ip';

class DNSRecordA extends DNSRecord {
  constructor() {
    super();
    this.type = DNSRecordType.A;
    this.address = '0.0.0.0';
  }

  _serializeData(writer) {
    let addr = this.address.split('.');
    if (addr.length !== 4) throw new Error('Invalid IPv4 address');
    for (let seg of addr) {
      writer.writeUInt8(parseInt(seg));
    }
  }

  _deserializeData(reader, rdlength) {
    if (rdlength !== 4) {
      throw new Error('Invalid A record');
    }
    let seg = new Array(4);
    for (let i = 0; i < 4; i++)
      seg[i] = reader.readUInt8();

    this.address = seg.join('.');
  }
}

class DNSRecordNS extends DNSRecord {
  constructor() {
    super();
    this.type = DNSRecordType.NS;
    this.nameserver = '';
  }

  _serializeData(writer) {
    writer.writeName(this.nameserver);
  }

  _deserializeData(reader, rdlength) {
    let ptr = reader._ptr;
    this.nameserver = reader.readName();
    if (ptr + rdlength !== reader._ptr) {
      throw new Error('Invalid NS record');
    }
  }
}

class DNSRecordCNAME extends DNSRecord {
  constructor() {
    super();
    this.type = DNSRecordType.CNAME;
    this.cname = '';
  }

  _serializeData(writer) {
    writer.writeName(this.cname);
  }

  _deserializeData(reader, rdlength) {
    let ptr = reader._ptr;
    this.cname = reader.readName();
    if (ptr + rdlength !== reader._ptr) {
      throw new Error('Invalid CNAME record');
    }
  }
}

class DNSRecordSOA extends DNSRecord {
  constructor() {
    super();
    this.type = DNSRecordType.SOA;
    this.mname = '';
    this.rname = '';
    this.serial = 0;
    this.refresh = 0;
    this.retry = 0;
    this.expire = 0;
    this.minimum = 0;
  }

  _serializeData(writer) {
    writer
      .writeName(this.mname)
      .writeName(this.rname)
      .writeUInt32BE(this.serial)
      .writeInt32BE(this.refresh)
      .writeInt32BE(this.retry)
      .writeInt32BE(this.expire)
      .writeInt32BE(this.minimum);
  }

  _deserializeData(reader, rdlength) {
    let ptr = reader._ptr;
    this.mname = reader.readName();
    this.rname = reader.readName();
    this.serial = reader.readUInt32BE();
    this.refresh = reader.readInt32BE();
    this.retry = reader.readInt32BE();
    this.expire = reader.readInt32BE();
    this.minimum = reader.readInt32BE();
    if (ptr + rdlength !== reader._ptr) {
      throw new Error('Invalid CNAME record');
    }
  }
}

class DNSRecordPTR extends DNSRecord {
  constructor() {
    super();
    this.type = DNSRecordType.PTR;
    this.domain = '';
  }

  _serializeData(writer) {
    writer.writeName(this.domain);
  }

  _deserializeData(reader, rdlength) {
    let ptr = reader._ptr;
    this.domain = reader.readName();
    if (ptr + rdlength !== reader._ptr) {
      throw new Error('Invalid PTR record');
    }
  }
}

class DNSRecordMX extends DNSRecord {
  constructor() {
    super();
    this.type = DNSRecordType.MX;
    this.preference = 0;
    this.exchange = '';
  }

  _serializeData(writer) {
    writer
      .writeInt16BE(this.preference)
      .writeName(this.exchange);
  }

  _deserializeData(reader, rdlength) {
    let ptr = reader._ptr;
    this.preference = reader.readInt16BE();
    this.exchange = reader.readName();
    if (ptr + rdlength !== reader._ptr) {
      throw new Error('Invalid MX record');
    }
  }
}

class DNSRecordTXT extends DNSRecord {
  constructor() {
    super();
    this.type = DNSRecordType.TXT;
    this.data = '';
  }

  _serializeData(writer) {
    writer.writeCharString(this.data);
  }

  _deserializeData(reader, rdlength) {
    let ptr = reader._ptr;
    this.data = reader.readCharString();
    if (ptr + rdlength !== reader._ptr) {
      throw new Error('Invalid MX record');
    }
  }
}

class DNSRecordAAAA extends DNSRecord {
  constructor() {
    super();
    this.type = DNSRecordType.AAAA;
    this.address = '::';
  }

  _serializeData(writer) {
    let bits = IPv6.textToBits(this.address);
    for (let i = 0; i < 8; i++) {
      writer.writeUInt16BE(bits[i]);
    }
  }

  _deserializeData(reader, rdlength) {
    if (rdlength !== 16) {
      throw new Error('Invalid AAAA record');
    }
    let bits = new Array(8);
    for (let i = 0; i < 8; i++) {
      bits[i] = reader.readUInt16BE();
    }
    this.address = bits.map(x => x.toString(16)).join(':');
  }
}


DNSRecord._registry[DNSRecordType.A] = DNSRecordA;
DNSRecord._registry[DNSRecordType.NS] = DNSRecordNS;
// TYPE MD is obsolete
// TYPE MF is obsolete
DNSRecord._registry[DNSRecordType.CNAME] = DNSRecordCNAME;
DNSRecord._registry[DNSRecordType.SOA] = DNSRecordSOA;
// Type MB is experimental
// Type MG is experimental
// Type MR is experimental
// Type NULL is experimental
// Type WKS not yet implemented
DNSRecord._registry[DNSRecordType.PTR] = DNSRecordPTR;
// Type HINFO not yet implemented
// Type MINFO not yet implemented
DNSRecord._registry[DNSRecordType.MX] = DNSRecordMX;
DNSRecord._registry[DNSRecordType.TXT] = DNSRecordTXT;

DNSRecord._registry[DNSRecordType.AAAA] = DNSRecordAAAA;

export {
  DNSRecordA,
  DNSRecordNS,
  DNSRecordCNAME,
  DNSRecordSOA,
  DNSRecordPTR,
  DNSRecordMX,
  DNSRecordTXT,

  DNSRecordAAAA,
};

