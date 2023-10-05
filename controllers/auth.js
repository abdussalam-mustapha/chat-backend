const jwt = require("jsonwebtoken")
const otpGenerator = require("otp-generator")
const crypto = require("crypto")

const mailService = require("../services/mailer")


const User = require("../models/user")
const filterObj = require("../utils/filterObj")
const { promisify } = require("util")

const signToken = (userId) => jwt.sign({ userId }, process.env.JWT_SECRET)

// signup = > register - sendOTP - verify OTP

// https://api.chatNow.com/auth/register

// register new user

exports.register = async (req, res, next) => {
    const { firstName, lastName, email, password } = req.body

    const filteredBody = filterObj(req.body, "firstName", "lastName", "password", "email")

    // check if a verified user with given email exists

    const existing_user = await User.findOne({ email: email })

    if (existing_user && existing_user.verified) {
        res.status(400).json({
            status: "error",
            message: "Email is already in use, please login"
        })
    }
    else if (existing_user) {
        await User.findOneAndUpdate({ email: email }, filteredBody, { new: true, validateModifiedOnly: true })

        req.userId = existing_user._id
        next()
    }
    else {
        // if user record is not available in DB

        const new_user = await User.create(filteredBody)

        // generate otp and send email to the user

        req.userId = new_user._id
        next()
    }
}

exports.sendOTP = async (req, res, next) => {
    const { userId } = req;
    const new_otp = otpGenerator.generate(6, { lowerCaseAlphabets: false, upperCaseAlphabets: false, specialChars: false })
    const otp_expiry_time = Date.now() + 10 * 60 * 1000

    await User.findByIdAndUpdate(userId, {
        otp: new_otp,
        otp_expiry_time,
    })

    // send email

    mailService.sendEmail({
        from: "abdussalammustapha07@gmail.com",
        to: "example@gmail.com",
        subject: "OTP for chatNow",
        text: `your OTP is ${new_otp}, this is valid for 10 mins`
    })

    res.status(200).json({
        status: "success",
        message: "OTP sent successfully"
    })
}

exports.verifyOTP = async (req, res, next) => {
    // verify OTP and update user records accordingly

    const { email, otp } = req.body

    const user = await User.findOne({
        email,
        otp_expiry_time: { $gt: Date.now() }
    })

    if (!user) {
        res.status(400).json({
            status: "error",
            message: "Email is invalid ot OTP expired"
        })
    }
    if (!await user.correctOTP(otp, user.otp)) {
        res.status(400).json({
            status: "error",
            message: "otp is incorrect"
        })
    }

    // otp is correct

    user.verified = true;
    user.otp = undefined;

    await user.save({ new: true, validateModifiedOnly: true });

    const token = signToken(user._id);

    res.status(200).json({
        status: "success",
        message: "OTP verified successfully",
        token
    })
}

exports.login = async (req, res, next) => {
    const { email, password } = req.body;

    if (!email || !password) {
        res.status(400).json({
            status: "error",
            message: "Both email and password are required"
        })
    }

    const userDoc = await User.findOne({ email: email }).select("+password")

    if (!userDoc || !(await userDoc.correctPassword(password, userDoc.password))) {
        res.status(400).json({
            status: "error",
            message: 'Email or password is incorrect'
        })
    }


    const token = signToken(userDoc._id);

    res.status(200).json({
        status: "success",
        message: "logged in successfully",
        token
    })
}

exports.protect = async (req, res, next) => {
    // getting token (JWT) and check if its actually there
    let token

    if (req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
        token = req.headers.authorization.split(" ")[1];
    }
    else if (req.cookies.jwt) {
        token = req.cookies.jwt
    }
    else {
        req.status(400).json({
            status: "error",
            message: "You are not logged in, please log in to get access"
        })

        return;
    }

    // 2 verification of token

    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

    // 3 check if user still exists

    const this_user = await User.findById(decoded.userId);

    if (!this_user) {
        res.status(400).json({
            status: "success",
            message: "the user doesn't exist"
        })
    }

    // check if user changed their password after token was issued

    if (this_user.changedPasswordAfter(decoded.iat)) {
        res.status(400).json({
            status: "error",
            message: "user recently updated password! please login again"
        })
    }

    // 

    req.user = this_user

    next();


}

// types of routes, protected routes (only logged in user can access it) & unprotected routes

exports.forgotPassword = async (req, res, next) => {
    // get user email 
    const user = await User.findOne({ email: req.body.email })
    if (!user) {
        res.status(400).json({
            status: "error",
            message: "there is no user with the given email address"
        })

        return;
    }

    // generate the random string token

    const resetToken = user.createPasswordResetToken();

    const resetURL = "https://chatNow.com/auth/reset-password/?code{resetToken}"

    try {

        // send email with reset url

        res.status(200).json({
            status: "success",
            message: ""
        })

    }
    catch (error) {
        user.passwordResetToken = undefined;

        user.passwordResetExpires = undefined;

        await user.save({ validateBeforeSave: false })

        res.status(500).json({
            status: "error",
            message: "There was an error sending the email, Please try again later."
        })
    }

    // https: 
}

exports.resetPassword = async (req, res, next) => {
    //  Get user based on token

    const hashedToken = crypto.createHash("sha256").update(req.params.token).digest("hex")

    const user = await User.findOne({
        passwordResetToken: hashedToken,
        passwordResetExpires: { $gt: Date.now() }
    })

    // if token has expired or submission is out of time window

    if (!user) {
        res.status(400).json({
            status: "error",
            message: "Token has expired"
        })

        return;
    }

    // update users password and set reset token and expirity to undefined

    user.password = req.body.password
    user.passwordConfirm = req.body.passwordConfirm
    user.passwordResetToken = undefined;

    user.passwordResetExpires = undefined;

    await user.save();

    // Login the user and send new JWT
    // send email to user informing about password reset

    const token = signToken(user._id);

    res.status(200).json({
        status: "success",
        message: "password reset successfully",
        token
    })
}