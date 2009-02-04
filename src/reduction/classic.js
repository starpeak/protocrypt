// Copyright 2009  StarPeak OnlineMedia, Sven G. Brönstrup
// Based on jsbn library - (c) 2005  Tom Wu
// Released under MIT licence

// Modular reduction using "classic" algorithm
Crypt.Reduction.Classic=Class.create({
  m: null,
  
  initialize: function(m) {
    this.m = m; 
  },
  
  convert: function(x) {
    if(x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
    else return x;
  },
  
  revert: function(x) { return x; },
  reduce: function(x) { x.divRemTo(this.m,null,x); },
  mulTo: function(x,y,r) { x.multiplyTo(y,r); this.reduce(r); },
  sqrTo: function(x,r) { x.squareTo(r); this.reduce(r); }
});