let userModel = require('../schemas/users')
const bcrypt = require("bcrypt")

module.exports = {

    // ===== CREATE USER =====
    CreateAnUser: async function (
        username, password, email, role, fullname, avatarUrl, status, loginCount) {

        const salt = await bcrypt.genSalt(10)
        const hashPassword = await bcrypt.hash(password, salt)

        let newUser = new userModel({
            username: username,
            password: hashPassword,
            email: email,
            fullName: fullname,
            avatarUrl: avatarUrl,
            status: status,
            role: role,
            loginCount: loginCount
        });

        await newUser.save();
        return newUser;
    },


    // ===== FIND USER BY USERNAME =====
    FindUserByUsername: async function (username) {

        return await userModel.findOne({
            username: username,
            isDeleted: false
        })

    },


    // ===== FIND USER BY ID =====
    FindUserById: async function (id) {

        try {

            return await userModel.findOne({
                _id: id,
                isDeleted: false
            })

        } catch (error) {

            return false
        }

    },


    // ===== CHANGE PASSWORD =====
    ChangePassword: async function (userId, oldPassword, newPassword) {

        let user = await userModel.findOne({
            _id: userId,
            isDeleted: false
        })

        if (!user) {
            return { error: "User khong ton tai" }
        }

        const checkPassword = await bcrypt.compare(oldPassword, user.password)

        if (!checkPassword) {
            return { error: "Mat khau cu khong dung" }
        }

        const salt = await bcrypt.genSalt(10)
        const newPasswordHash = await bcrypt.hash(newPassword, salt)

        user.password = newPasswordHash

        await user.save()

        return { message: "Doi mat khau thanh cong" }
    }

}