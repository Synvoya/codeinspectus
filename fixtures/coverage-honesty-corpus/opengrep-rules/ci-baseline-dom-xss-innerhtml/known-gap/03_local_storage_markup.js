// KNOWN GAP (documented): stored markup (localStorage) needs a sanitizer-aware stored-XSS model.
$("#draft").html(localStorage.getItem("draft"));
