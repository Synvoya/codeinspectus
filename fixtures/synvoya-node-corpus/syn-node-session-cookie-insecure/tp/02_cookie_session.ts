import cookieSession from "cookie-session";
export const middleware = cookieSession({ name: "sess", keys: [process.env.K as string], httpOnly: false });
