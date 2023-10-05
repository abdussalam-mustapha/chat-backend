const express = require("express")

const routes = require("./routes/index")

const morgan = require("morgan")

const rateLimit = require("express-rate-limit")

const mongosanitize = require("express-mongo-sanitize")

const bodyParser = require("body-parser")

const xss = require("xss")

const cors = require("cors")

const helmet = require("helmet")

const app = express();

app.use(cors({
    origin: "*",
    methods: ["GET", "PATCH", "POST", "DELETE", "PUT"],
    credentials: true
}))

app.use(express.json({ limit: "10kb" }))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))
app.use(helmet())

if (process.env.NODE_ENV === "development") {
    app.use(morgan("dev"))
}

const limiter = rateLimit({
    max: 3000,
    windowMs: 60 * 60 * 1000,
    message: "too many request on this IP, please try again later"
})

app.use("/chatNow", limiter)

app.use(routes)

app.use(express.urlencoded({
    extended: true,
}))

app.use(mongosanitize())

// app.use(xss())


module.exports = app;