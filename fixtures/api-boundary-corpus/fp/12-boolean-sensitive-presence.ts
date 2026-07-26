export function handler(request: any) {
  request.log.info({ authorizationPresent: Boolean(request.headers.authorization) })
  request.log.info({ hasCookie: !!request.cookies })
}
