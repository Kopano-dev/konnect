export function withClientRequestState(obj) {
  obj.state = Math.random().toString(36).substring(7);

  return obj;
}

export function propertyFromStylesheet(selector, attribute) {
  var value;

  Array.prototype.some.call(document.styleSheets, function(sheet) {
    return Array.prototype.some.call(sheet.cssRules, function(rule) {
      if (selector === rule.selectorText) {
        return Array.prototype.some.call(rule.style, function(style) {
          if (attribute === style) {
            value = rule.style.getPropertyValue(attribute);
            return true;
          }

          return false;
        });
      }

      return false;
    });
  });

  return value;
}

export function enhanceBodyBackground() {
  const url = propertyFromStylesheet('#bg-enhanced.enhanced', 'background-image');

  if (url) {
    const img = new Image();
    img.onload = () => {
      window.document.getElementById('bg-enhanced').className += ' enhanced';
    };

    // Set image source to whatever the url from css holds.
    img.src = url.match(/(?:\(['|"]?)(.*?)(?:['|"]?\))/)[1];
  }
}
