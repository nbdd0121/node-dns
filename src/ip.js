export class IPv4 {
  static textToBits(address) {
    let parts = address.split('.');

    // Only 4 parts are allowed
    if (parts.length !== 4) throw new Error('Invalid IPv4 address');
    
    let bits = new Array(4);

    for (let i = 0; i < 4; i++) {
      // n must be a decimal number
      let n = parseInt(parts[i], 10);
      if (n < 0 || n >= 255) throw new Error('Invalid IPv4 address');
      // Representation of IPv4 address requires no leading zeros
      // i.e. 192.168.00.1 is invalid
      if (n.toString() !== parts[i]) throw new Error('Invalid IPv4 address');

      bits[i] = n;
    }

    return bits;
  }
}

export class IPv6 {
  static _parseTextParts(text) {
    return text.split(':').map(part => {
      if(/[A-Za-z0-9]{1,4}/.test(part)) {
        return parseInt(part, 16);
      } else {
        throw new Error('Invalid IPv6 address');
      }
    });
  }

  static textToBits(address) {
    let halves = address.split('::');

    // Ellission can only appear once
    if (halves.length > 2) throw new Error('Invalid IPv6 address: Too many ellisions');

    let latter = halves[halves.length - 1];
    // Contains IPv4 address
    if (latter.indexOf('.') !== -1) {
      let id = latter.lastIndexOf(':');
      let ip4 = IPv4.textToBits(latter.substr(id + 1));
      let a = ((ip4[0] << 8) | ip4[1]).toString(16);
      let b = ((ip4[2] << 8) | ip4[3]).toString(16);
      latter = latter.substr(0, id + 1) + a + ':' + b;
    }

    // Without ellision
    if (halves.length === 1) {
      let bits = IPv6._parseTextParts(latter);
      if (bits.length !== 8) throw new Error('Invalid IPv6 address: Incorrect number of groups');
      return bits;
    }

    let former = halves[0];
    if (former === '') {
      if (latter === '') return new Array(8).fill(0);
      let bits = IPv6._parseTextParts(latter);
      if (bits.length >= 8) throw new Error('Invalid IPv6 address: Incorrect number of groups');
      bits.unshift(...new Array(8 - bits.length).fill(0));
      return bits;
    }

    if (latter === '') {
      let bits = IPv6._parseTextParts(former);
      if (bits.length >= 8) throw new Error('Invalid IPv6 address: Incorrect number of groups');
      bits.push(...new Array(8 - bits.length).fill(0));
      return bits;
    }

    let a = IPv6._parseTextParts(former);
    let b = IPv6._parseTextParts(latter);
    if (a.length + b.length >= 8) if (bits.length !== 8) throw new Error('Invalid IPv6 address: Incorrect number of groups');
    return [...a, ...new Array(8 - a.length - b.length).fill(0), ...b];
  }
}
