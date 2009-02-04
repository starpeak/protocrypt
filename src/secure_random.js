// Copyright 2009  StarPeak OnlineMedia, Sven G. Brönstrup
// Based on jsbn library - (c) 2005  Tom Wu
// Released under MIT licence

Crypt.SecureRandom=Class.create({
  state: null,
  pool: null,
  pptr: null,
  
  initialize: function() {
    // Initialize the pool with junk if needed.
    if(this.pool == null) {
      this.pool = new Array();
      this.pptr = 0;
      var t;
      if(navigator.appName == "Netscape" && navigator.appVersion < "5" && window.crypto) {
        // Extract entropy (256 bits) from NS4 RNG if available
        var z = window.crypto.random(32);
        for(t = 0; t < z.length; ++t)
          this.pool[this.pptr++] = z.charCodeAt(t) & 255;
      }  
      while(this.pptr < Crypt.psize) {  // extract some randomness from Math.random()
        t = Math.floor(65536 * Math.random());
        this.pool[this.pptr++] = t >>> 8;
        this.pool[this.pptr++] = t & 255;
      }
      this.pptr = 0;
      this.seed_time();
      //this.seed_int(window.screenX);
      //this.seed_int(window.screenY);
    }  
  },

  // Mix in a 32-bit integer into the pool
  seed_int: function(x) {
    this.pool[this.pptr++] ^= x & 255;
    this.pool[this.pptr++] ^= (x >> 8) & 255;
    this.pool[this.pptr++] ^= (x >> 16) & 255;
    this.pool[this.pptr++] ^= (x >> 24) & 255;
    if(this.pptr >= Crypt.psize) this.pptr -= Crypt.psize;
  },
  
  // Mix in the current time (w/milliseconds) into the pool
  seed_time: function() {
    this.seed_int(new Date().getTime());
  },
  
  get_byte: function() {
    if(this.state == null) {
      this.seed_time();
      this.state = new Crypt.SecureState(this.pool);
      for(this.pptr = 0; this.pptr < this.pool.length; ++this.pptr)
        this.pool[this.pptr] = 0;
      this.pptr = 0;
      //this.pool = null;
    }
    // TODO: allow reseeding after first request
    return this.state.next();
  },

  nextBytes: function(ba){
    var i;
    for (i = 0; i < ba.length; ++i) 
      ba[i] = this.get_byte();
  }
});