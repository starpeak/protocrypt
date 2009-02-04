// Copyright 2009  StarPeak OnlineMedia, Sven G. Brönstrup
// Based on jsbn library - (c) 2005  Tom Wu
// Released under MIT licence
  
// FORM HELPER
// ToDo: Only add method to form

Element.addMethods({
  request_secure: function(form, options) {
    var action = form.readAttribute('action') || '';
    if (action.blank()) action = window.location.href;
  
    if (form.hasAttribute('method') && !options.method)
      options.method = form.method;
  
    c=new Crypt.RSA();
    c.setPublic(
      options.n, options.e
    );
    values=new Hash(form.serialize(true));
    secure=new Hash();
    if(!options.parameters) {
      options.parameters=new Hash();
    }
    values.each(function(pair){
      secure.set(pair.key,c.encrypt(pair.value.utf8_encode()));
    })
    options.parameters.set('secureValues',secure.toQueryString());
    
    return new Ajax.Request(action, options);
  }
});
