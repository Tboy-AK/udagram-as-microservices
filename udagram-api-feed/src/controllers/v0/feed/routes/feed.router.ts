import { Router, Request, Response } from "express";
import { FeedItem } from "../models/FeedItem";
import { NextFunction } from "connect";
import * as jwt from "jsonwebtoken";
import logger from "../../../../config/logger";
import { v4 as uuid4 } from "uuid";
import * as AWS from "../../../../aws";
import * as c from "../../../../config/config";

const router: Router = Router();

export function requireAuth(req: Request, res: Response, next: NextFunction) {
    req.headers.request_id = uuid4();
    logger.info(
        `User requesting secure route :: req-${req.headers.request_id}`
    );

    if (!req.headers || !req.headers.authorization) {
        logger.info(
            `User requesting secure route failed. No Authorization header :: req-${req.headers.request_id}`
        );
        return res.status(401).send({ message: "No authorization headers." });
    }

    const tokenBearer = req.headers.authorization.split(" ");
    if (tokenBearer.length != 2) {
        logger.info(
            `User requesting secure route failed. Malformed token :: req-${req.headers.request_id}`
        );
        return res.status(401).send({ message: "Malformed token." });
    }

    const token = tokenBearer[1];
    return jwt.verify(token, c.config.jwt.secret, (err) => {
        if (err) {
            logger.info(
                `User requesting secure route failed. Authentication failed :: req-${req.headers.request_id}`
            );
            return res
                .status(500)
                .send({ auth: false, message: "Failed to authenticate." });
        }
        req.headers.REQUEST_ID;
        return next();
    });
}

// Get all feed items
router.get("/", async (req: Request, res: Response) => {
    logger.info(`User requesting all feed items :: req-${uuid4()}`);
    const items = await FeedItem.findAndCountAll({ order: [["id", "DESC"]] });
    items.rows.forEach((item) => {
        if (item.url) {
            item.url = AWS.getGetSignedUrl(item.url);
        }
    });
    res.send(items);
});

// Get a feed resource
router.get("/:id", async (req: Request, res: Response) => {
    logger.info(`User requesting a feed resource :: req-${uuid4()}`);
    const { id } = req.params;
    const item = await FeedItem.findByPk(id);
    res.send(item);
});

// Get a signed url to put a new item in the bucket
router.get(
    "/signed-url/:fileName",
    requireAuth,
    async (req: Request, res: Response) => {
        logger.info(
            `System retrieving signed URL for user photo upload :: req-${req.headers.request_id}`
        );

        const { fileName } = req.params;
        const url = AWS.getPutSignedUrl(fileName);
        res.status(201).send({ url: url });
    }
);

// Create feed with metadata
router.post("/", requireAuth, async (req: Request, res: Response) => {
    logger.info(
        `User requesting to create feed :: req-${req.headers.request_id}`
    );

    const caption = req.body.caption;
    const fileName = req.body.url; // same as S3 key name

    if (!caption) {
        logger.info(
            `User requesting to create feed failed. Invalid caption :: req-${req.headers.request_id}`
        );
        return res
            .status(400)
            .send({ message: "Caption is required or malformed." });
    }

    if (!fileName) {
        logger.info(
            `User requesting to create feed failed. No file URL :: req-${req.headers.request_id}`
        );
        return res.status(400).send({ message: "File url is required." });
    }

    const item = new FeedItem({
        caption: caption,
        url: fileName,
    });

    const savedItem = await item.save();

    savedItem.url = AWS.getGetSignedUrl(savedItem.url);

    logger.info(
        `User requesting to create feed successful :: req-${req.headers.request_id}`
    );

    res.status(201).send(savedItem);
});

export const FeedRouter: Router = router;
