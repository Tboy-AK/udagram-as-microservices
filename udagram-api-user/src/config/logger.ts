import { createLogger, format, transports } from "winston";
import DailyRotateFile from "winston-daily-rotate-file";

const customFormat = format.printf(
    ({ level, message, reqId, timestamp, ms, stack }) => {
        const errorStack =
            stack && typeof message === "string" && message.includes(stack)
                ? `\n${stack}`
                : "";
        return `${timestamp} ${ms} [${
            reqId || "-"
        }] ${level}: ${message}${errorStack}`;
    }
);

const options = {
    file: {
        level: "http",
        dirname: "/opt/logs",
        filename: "%DATE%.log",
        datePattern: "YYYY-MM-DD",
        maxSize: "512m",
        maxFiles: 2,
        colorize: false,
        handleExceptions: true,
        handleRejections: true,
    },
    console: {
        level: "debug",
        handleExceptions: true,
        handleRejections: true,
        format: format.combine(
            format.timestamp(),
            format.ms(),
            format.simple(),
            format.colorize({ all: true }),
            customFormat
        ),
        colorize: true,
    },
};

const loggerOptions = {
    level: "info",
    transports: [
        new transports.Console(options.console),
        new DailyRotateFile(options.file),
    ],
};

const logger = createLogger({
    transports: loggerOptions.transports,
    // Do not exit on handled exceptions
    exitOnError: false,
});

// Stream logs
logger.stream({
    write(message: any) {
        logger.info(message);
    },
});

export default logger;
