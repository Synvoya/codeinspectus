import secureHeaders from "helmet";

app.use(secureHeaders({
  referrerPolicy: false,
  permissionsPolicy: false,
}));
