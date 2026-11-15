// Browser upload helper: XMLHttpRequest.send is a request, not a server response.
export function reportUploadFailure(endpoint: string, err: Error) {
  const xhr = new XMLHttpRequest();
  xhr.open("POST", endpoint);
  xhr.setRequestHeader("content-type", "application/json");
  xhr.send(JSON.stringify({ error: err.message, stack: err.stack }));
}
