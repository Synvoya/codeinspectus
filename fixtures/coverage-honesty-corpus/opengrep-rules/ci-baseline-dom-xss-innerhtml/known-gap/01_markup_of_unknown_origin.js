// Known gap (precision pass, design 10.6): markup whose origin is not a DOM-XSS source in this file
// (a parameter, a server response) is not reported. Field triage found these writes almost always safe.
module.exports = (el, html) => {
  el.innerHTML = html;
};
