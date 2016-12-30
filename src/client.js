import dgram from 'dgram';
import dns from 'dns';
import {DNSQuestion, DNSRecord, DNSPacket} from './packet';
import {} from './record';
import Defer from './defer';

class DNSRequest {
  constructor(packet, client, options) {
    this.id = packet.id;
    this.packet = packet.toBuffer();

    this.client = client;

    this.defer = Defer();
    this.timeout = 0;

    this.options = options;
    this.retry = this.options.retry;
  }

  track() {
    this.client._req[this.id] = this;
    this.timeout = setTimeout(() => this.onTimeout(), this.options.timeout);
    this.send();
    this.client._dgram.ref();
  }

  send() {
    this.client._dgram.send(this.packet, 53, this.options.server, (err) => {
      if (err) {
        this.removeSelf();
        this.defer.reject(err);
      }
    });
  }

  onPacket(packet, rinfo) {
    // if (rinfo.address !== this.server) return;
    this.removeSelf();
    this.defer.resolve(packet);
  }

  onTimeout() {
    if (this.retry <= 0) {
      this.removeSelf();
      let error = new Error(`ETIMEDOUT: DNS query timed out after ${this.options.retry + 1} trials each with ${this.options.timeout}ms timeout`);
      error.code = 'ETIMEDOUT';
      this.defer.reject(error);
    } else {
      this.retry--;
      this.send();
      this.timeout = setTimeout(() => this.onTimeout(), this.options.timeout);
    } 
  }

  removeSelf() {
    if (this.timeout) clearTimeout(this.timeout);
    delete this.client._req[this.id];
    this.client._dgram.unref();
  }
}

export default class DNSClient {
  constructor(options = {}) {
    if (typeof options !== 'object') throw new TypeError('options need to be object');

    let family = options.family || 4;
    if (family !== 4 && family !== 6) throw new Error('family must be either 4 or 6');

    this._server = options.server || dns.getServers()[0];
    
    this._dgram = dgram.createSocket('udp' + family);
    this._id = 0;
    this._req = Object.create(null);

    this._dgram.on('error', (err) => {
      // Treat as fatal error. Terminate all pending requests
      for (let r of this._req) {
        r.removeSelf();
        r.defer.promise.reject(err);
      }
    });

    this._dgram.on('message', (msg, rinfo) => {
      try {
        let p = DNSPacket.fromBuffer(msg);
        // Basic sanitiy check
        if (!p.isResponse) return;
        if (!(p.id in this._req)) return;
        this._req[p.id].onPacket(p);
      } catch (e) {
      }
    });

    this._dgram.unref();
  }

  send(packet, options = {}) {
    packet.id = this._id++;

    if (typeof options !== 'object') throw new TypeError('options need to be object');
    options.retry = options.retry || 1;
    options.timeout = options.timeout || 2000;
    options.server = options.server || this._server;

    // Create and track request
    let req = new DNSRequest(packet, this, options);
    req.track();
    return req.defer.promise;
  }

  close() {
    this._dgram.close();
  }

}


