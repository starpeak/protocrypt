// Copyright 2009  StarPeak OnlineMedia, Sven G. Brönstrup
// Based on jsbn library - (c) 2005  Tom Wu
// Released under MIT licence

Crypt.RSA=Class.create({
  n: null,
  e: 0,
  d: null,
  p: null,
  q: null,
  dmp1: null,
  dmq1: null,
  coeff: null,

  // PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
  pkcs1pad2: function(s,n) {
    if(n < s.length + 11) {
      alert("Message too long for RSA\n\nmaximum: " + (n-11) + "\nactual: " + (s.length));
      return null;
    }
    var ba = new Array();
    var i = s.length - 1;
    while(i >= 0 && n > 0) ba[--n] = s.charCodeAt(i--);
    ba[--n] = 0;
    var rng = new Crypt.SecureRandom();
    var x = new Array();
    while(n > 2) { // random non-zero pad
      x[0] = 0;
      while(x[0] == 0) rng.nextBytes(x);
      ba[--n] = x[0];
    }
    ba[--n] = 2;
    ba[--n] = 0;
    return new Crypt.BigInt(ba);
  },

  // Set the public key fields N and e from hex strings
  setPublic: function(N,E) {
    if(N != null && E != null && N.length > 0 && E.length > 0) {
      this.n = new Crypt.BigInt(N,16);
      this.e = parseInt(E,16);
    }
    else
      alert("Invalid RSA public key");
  },
  
  // Perform raw public operation on "x": return x^e (mod n)
  doPublic: function(x) {
    return x.modPowInt(this.e, this.n);
  },
  
  // Return the PKCS#1 RSA encryption of "text" as an even-length hex string
  encrypt: function(text) {
    var m = this.pkcs1pad2(text,(this.n.bitLength()+7)>>3);
    if(m == null) return null;
    var c = this.doPublic(m);
    if(c == null) return null;
    var h = c.toString(16);
    if((h.length & 1) == 0) return h; else return "0" + h;
  }
});