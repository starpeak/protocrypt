// Copyright 2009  StarPeak OnlineMedia, Sven G. Brönstrup
// Based on jsbn library - (c) 2005  Tom Wu
// Released under MIT licence
  
Crypt={
  // Pool size must be a multiple of 4 and greater than 32.
  // An array of bytes the size of the pool will be passed to init()
  psize: 256,
}

Crypt.Base = {
  BI_RM: "0123456789abcdefghijklmnopqrstuvwxyz",
  BI_RC: new Array(),

  
  init: function() {
    var canary = 0xdeadbeefcafe;
    var j_lm = ((canary&0xffffff)==0xefcafe);
    
    if(j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
      Crypt.Base.am = Crypt.Base.am2;
      Crypt.Base.dbits = 30;
    }
    else if(j_lm && (navigator.appName != "Netscape")) {
      Crypt.Base.am = Crypt.Base.am1;
      Crypt.Base.dbits = 26;
    }
    else { // Mozilla/Netscape seems to prefer am3
      Crypt.Base.am = Crypt.Base.am3;
      Crypt.Base.dbits = 28;
    }  
    
    var rr,vv;
    rr = "0".charCodeAt(0);
    for(vv = 0; vv <= 9; ++vv) Crypt.Base.BI_RC[rr++] = vv;
    rr = "a".charCodeAt(0);
    for(vv = 10; vv < 36; ++vv) Crypt.Base.BI_RC[rr++] = vv;
    rr = "A".charCodeAt(0);
    for(vv = 10; vv < 36; ++vv) Crypt.Base.BI_RC[rr++] = vv;  
  },
  
  // am: Compute w_j += (x*this_i), propagate carries,
  // c is initial carry, returns final carry.
  // c < 3*dvalue, x < 2*dvalue, this_i < dvalue
  // We need to select the fastest one that works in this environment.
  
  // am1: use a single mult and divide to get the high bits,
  // max digit bits should be 26 because
  // max internal value = 2*dvalue^2-2*dvalue (< 2^53)
  am1: function(i,x,w,j,c,n) {
    while(--n >= 0) {
      var v = x*this[i++]+w[j]+c;
      c = Math.floor(v/0x4000000);
      w[j++] = v&0x3ffffff;
    }
    return c;
  },
  // am2 avoids a big mult-and-extract completely.
  // Max digit bits should be <= 30 because we do bitwise ops
  // on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
  am2: function(i,x,w,j,c,n) {
    var xl = x&0x7fff, xh = x>>15;
    while(--n >= 0) {
      var l = this[i]&0x7fff;
      var h = this[i++]>>15;
      var m = xh*l+h*xl;
      l = xl*l+((m&0x7fff)<<15)+w[j]+(c&0x3fffffff);
      c = (l>>>30)+(m>>>15)+xh*h+(c>>>30);
      w[j++] = l&0x3fffffff;
    }
    return c;
  },
  // Alternately, set max digit bits to 28 since some
  // browsers slow down when dealing with 32-bit numbers.
  am3: function(i,x,w,j,c,n) {
    var xl = x&0x3fff, xh = x>>14;
    while(--n >= 0) {
      var l = this[i]&0x3fff;
      var h = this[i++]>>14;
      var m = xh*l+h*xl;
      l = xl*l+((m&0x3fff)<<14)+w[j]+c;
      c = (l>>28)+(m>>14)+xh*h;
      w[j++] = l&0xfffffff;
    }
    return c;
  },
  
    
  int2char: function(n) { return Crypt.Base.BI_RM.charAt(n); },
  
  intAt: function(s,i) {
    var c = Crypt.Base.BI_RC[s.charCodeAt(i)];
    return (c==null)?-1:c;
  },
  
  // returns bit length of the integer x
  nbits: function(x) {
    var r = 1, t;
    if((t=x>>>16) != 0) { x = t; r += 16; }
    if((t=x>>8) != 0) { x = t; r += 8; }
    if((t=x>>4) != 0) { x = t; r += 4; }
    if((t=x>>2) != 0) { x = t; r += 2; }
    if((t=x>>1) != 0) { x = t; r += 1; }
    return r;
  }
}

Crypt.Base.init();

Crypt.Reduction={}