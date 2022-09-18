import { Router, Request, Response } from "express";
import logger from "../../../../config/logger";
import { v4 as uuid4 } from "uuid";
import { User } from "../models/User";
import * as c from "../../../../config/config";
import * as bcrypt from "bcrypt";
import * as jwt from "jsonwebtoken";
import { NextFunction } from "connect";

import * as EmailValidator from "email-validator";

const router: Router = Router();

async function generatePassword(plainTextPassword: string): Promise<string> {
    const saltRounds = 10;
    const salt = await bcrypt.genSalt(saltRounds);
    return await bcrypt.hash(plainTextPassword, salt);
}

async function comparePasswords(
    plainTextPassword: string,
    hash: string
): Promise<boolean> {
    return await bcrypt.compare(plainTextPassword, hash);
}

function generateJWT(user: User): string {
    return jwt.sign(user.short(), c.config.jwt.secret);
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
    req.headers.request_id = uuid4();
    logger.info(
        `User requesting secure route :: req-${req.headers.request_id}`
    );

    if (!req.headers || !req.headers.authorization) {
        return res.status(401).send({ message: "No authorization headers." });
    }

    const tokenBearer = req.headers.authorization.split(" ");
    if (tokenBearer.length != 2) {
        return res.status(401).send({ message: "Malformed token." });
    }

    const token = tokenBearer[1];
    return jwt.verify(token, c.config.jwt.secret, (err, decoded) => {
        if (err) {
            return res
                .status(500)
                .send({ auth: false, message: "Failed to authenticate." });
        }
        return next();
    });
}

router.get(
    "/verification",
    requireAuth,
    async (req: Request, res: Response) => {
        logger.info(
            `User verifying authourised access :: req-${req.headers.request_id}`
        );
        return res.status(200).send({ auth: true, message: "Authenticated." });
    }
);

router.post("/login", async (req: Request, res: Response) => {
    const reqId = uuid4();
    logger.info(`User requesting login :: req-${reqId}`);

    const email = req.body.email;
    const password = req.body.password;

    if (!email || !EmailValidator.validate(email)) {
        logger.info(`Failed user login :: req-${reqId}`);
        return res
            .status(400)
            .send({ auth: false, message: "Email is required or malformed." });
    }

    if (!password) {
        logger.info(`Failed user login :: req-${reqId}`);
        return res
            .status(400)
            .send({ auth: false, message: "Password is required." });
    }

    const user = await User.findByPk(email);
    if (!user) {
        logger.info(`Failed user login :: req-${reqId}`);
        return res
            .status(401)
            .send({ auth: false, message: "User was not found.." });
    }

    const authValid = await comparePasswords(password, user.passwordHash);

    if (!authValid) {
        logger.info(`Failed user login :: req-${reqId}`);
        return res
            .status(401)
            .send({ auth: false, message: "Password was invalid." });
    }

    const jwt = generateJWT(user);
    res.status(200).send({ auth: true, token: jwt, user: user.short() });
});

router.post("/", async (req: Request, res: Response) => {
    const reqId = uuid4();
    logger.info(`User requesting registration :: req-${reqId}`);

    const email = req.body.email;
    const plainTextPassword = req.body.password;

    if (!email || !EmailValidator.validate(email)) {
        logger.info(`User registration failed. Invalid email :: req-${reqId}`);
        return res
            .status(400)
            .send({ auth: false, message: "Email is missing or malformed." });
    }

    if (!plainTextPassword) {
        logger.info(
            `User registration failed. Invalid password :: req-${reqId}`
        );
        return res
            .status(400)
            .send({ auth: false, message: "Password is required." });
    }

    const user = await User.findByPk(email);
    if (user) {
        logger.info(
            `User registration failed. User already exists :: req-${reqId}`
        );
        return res
            .status(422)
            .send({ auth: false, message: "User already exists." });
    }

    const generatedHash = await generatePassword(plainTextPassword);

    const newUser = new User({
        email: email,
        passwordHash: generatedHash,
    });

    const savedUser = await newUser.save();

    const jwt = generateJWT(savedUser);
    logger.info(`User registration successful :: req-${reqId}`);
    res.status(201).send({ token: jwt, user: savedUser.short() });
});

router.get("/", async (req: Request, res: Response) => {
    res.send("auth");
});

export const AuthRouter: Router = router;
