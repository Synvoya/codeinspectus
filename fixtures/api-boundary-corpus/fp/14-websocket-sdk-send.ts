// Client SDK: the token authenticates this client to the server over its own socket.
interface Socket { send(data: unknown): void }

export function authenticate(socket: Socket, access_token: string) {
  socket.send({ type: "auth", access_token });
}

export function resume(channel: Socket, token: string) {
  channel.send({ type: "resume", token });
}
