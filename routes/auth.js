let express = require('express')
let router = express.Router()
let userController = require('../controllers/users')
let { RegisterValidator, validatedResult } = require('../utils/validator')
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
const { check } = require('express-validator')
const { checkLogin } = require('../utils/authHandler')
const fs = require('fs')

// đọc private key
const privateKey = fs.readFileSync('private.key')


// ===== REGISTER =====
router.post('/register',
 RegisterValidator, validatedResult, async function (req, res, next) {

    let { username, password, email } = req.body;

    let newUser = await userController.CreateAnUser(
        username, password, email, '69b2763ce64fe93ca6985b56'
    )

    res.send(newUser)

})


// ===== LOGIN =====
router.post('/login', async function (req, res, next) {

    let { username, password } = req.body;

    let user = await userController.FindUserByUsername(username);

    if (!user) {
        res.status(404).send({
            message: "thong tin dang nhap khong dung"
        })
        return;
    }

    if (!user.lockTime || user.lockTime < Date.now()) {

        if (bcrypt.compareSync(password, user.password)) {

            user.loginCount = 0;
            await user.save();

            // ===== JWT RS256 =====
            let token = jwt.sign(
                {
                    id: user._id
                },
                privateKey,
                {
                    algorithm: "RS256",
                    expiresIn: "1h"
                }
            )

            res.send(token)

        } else {

            user.loginCount++;

            if (user.loginCount == 3) {
                user.loginCount = 0;
                user.lockTime = new Date(Date.now() + 60 * 60 * 1000)
            }

            await user.save();

            res.status(404).send({
                message: "thong tin dang nhap khong dung"
            })
        }

    } else {

        res.status(404).send({
            message: "user dang bi ban"
        })

    }

})


// ===== GET USER INFO =====
router.get('/me', checkLogin, function (req, res, next) {

    res.send(req.user)

})


// ===== CHANGE PASSWORD =====
router.post(
    '/change-password',
    checkLogin,

    check('oldPassword')
        .notEmpty()
        .withMessage('Old password khong duoc de trong'),

    check('newPassword')
        .isLength({ min: 6 })
        .withMessage('Password phai >= 6 ky tu'),

    validatedResult,

    async function (req, res) {

        let { oldPassword, newPassword } = req.body

        let user = await userController.FindUserById(req.user.id)

        if (!user) {
            return res.status(404).send({
                message: "User khong ton tai"
            })
        }

        if (!bcrypt.compareSync(oldPassword, user.password)) {
            return res.status(400).send({
                message: "Mat khau cu khong dung"
            })
        }

        let salt = bcrypt.genSaltSync(10)
        let hashPassword = bcrypt.hashSync(newPassword, salt)

        user.password = hashPassword

        await user.save()

        res.send({
            message: "Doi mat khau thanh cong"
        })

    }
)

module.exports = router