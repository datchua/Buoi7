let jwt = require('jsonwebtoken')
let fs = require('fs')
let userController = require("../controllers/users")

// đọc public key
const publicKey = fs.readFileSync("public.key")

module.exports = {

    checkLogin: async function (req, res, next) {

        try {

            let token = req.headers.authorization

            if (!token || !token.startsWith('Bearer')) {
                return res.status(401).send("ban chua dang nhap")
            }

            token = token.split(" ")[1]

            // verify token bằng RS256
            let result = jwt.verify(token, publicKey, {
                algorithms: ["RS256"]
            })

            if (result.exp * 1000 > Date.now()) {

                let user = await userController.FindUserById(result.id)

                if (user) {

                    req.user = user
                    next()

                } else {

                    res.status(401).send("ban chua dang nhap")

                }

            } else {

                res.status(401).send("token het han")

            }

        } catch (error) {

            res.status(401).send("ban chua dang nhap")

        }

    }

}