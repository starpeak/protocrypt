// Copyright 2009  StarPeak OnlineMedia, Sven G. Brönstrup
// Based on jsbn library - (c) 2005  Tom Wu
// Released under MIT licence

Crypt.SecureState=Class.create({
  i: 0,
  j: 0,
  S: new Array(),

  
  initialize: function(key) {
    var i, j, t;
    for(i = 0; i < 256; ++i)
      this.S[i] = i;
    j = 0;
    for(i = 0; i < 256; ++i) {
      j = (j + this.S[i] + key[i % key.length]) & 255;
      t = this.S[i];
      this.S[i] = this.S[j];
      this.S[j] = t;
    }
    this.i = 0;
    this.j = 0;
  },
  
  next: function() {
    var t;
    this.i = (this.i + 1) & 255;
    this.j = (this.j + this.S[this.i]) & 255;
    t = this.S[this.i];
    this.S[this.i] = this.S[this.j];
    this.S[this.j] = t;
    return this.S[(t + this.S[this.i]) & 255];
  }
});