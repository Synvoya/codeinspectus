export function handler(request: any) {
  request.log.info({ authorization: request.headers.authorization })
}
