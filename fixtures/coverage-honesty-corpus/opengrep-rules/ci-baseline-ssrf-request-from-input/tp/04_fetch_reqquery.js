export function h(request){
  return fetch(request.query + "?x=1");
}
