import { moduleRouter } from "./access";

const router = moduleRouter("hello-001");

router.get("/", (_req, res) => {
  res.json({
    message: "Hello from the server",
    time: new Date().toISOString(),
    user: res.locals.user.username,
  });
});

export default router;