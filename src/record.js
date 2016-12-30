import {DNSRecord} from './packet';

class DNSRecordA extends DNSRecord {
  constructor() {
    super();
    this.type = 1;
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
    this.type = 2;
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
    this.type = 5;
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
    this.type = 6;
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

DNSRecord._registry[1] = DNSRecordA;
DNSRecord._registry[2] = DNSRecordNS;
// TYPE 3 MD is obsolete
// TYPE 4 MF is obsolete
DNSRecord._registry[5] = DNSRecordCNAME;
DNSRecord._registry[6] = DNSRecordSOA;

export {
  DNSRecordA,
  DNSRecordNS,
  DNSRecordCNAME,
  DNSRecordSOA,
};

