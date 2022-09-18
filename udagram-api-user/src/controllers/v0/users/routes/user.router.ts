import { Router, Request, Response } from "express";
import * as winston from "winston";
import { v4 as uuid4 } from "uuid";

import { User } from "../models/User";
import { AuthRouter } from "./auth.router";

const router: Router = Router();

router.use("/auth", AuthRouter);

router.get("/");

router.get("/:id", async (req: Request, res: Response) => {
    winston.info(`User requesting secure route :: req-${uuid4()}`);
    const { id } = req.params;
    const item = await User.findByPk(id);
    res.send(item);
});

export const UserRouter: Router = router;
