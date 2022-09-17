import { Router } from "express";
import { UserRouter } from "./users/routes/user.router";

const router: Router = Router();

router.use("/users", UserRouter);

export const IndexRouter: Router = router;
