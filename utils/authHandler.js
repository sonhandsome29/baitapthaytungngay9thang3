let jwt = require('jsonwebtoken');
let userController = require('../controllers/users');

function normalizeRoleName(roleName) {
    let normalized = String(roleName || '').trim().toUpperCase();
    if (normalized === 'MODERATOR') return 'MOD';
    return normalized;
}

function getTokenFromRequest(req) {
    if (req.cookies && req.cookies.token) {
        return req.cookies.token;
    }

    let authorizationToken = req.headers.authorization;
    if (!authorizationToken || !authorizationToken.startsWith('Bearer ')) {
        return null;
    }

    return authorizationToken.split(' ')[1];
}

module.exports = {
    checkLogin: async function (req, res, next) {
        try {
            let token = getTokenFromRequest(req);
            if (!token) {
                return res.status(403).send({
                    message: 'ban chua dang nhap'
                });
            }

            let result = jwt.verify(token, 'HUTECH');
            if (!result.exp || result.exp <= Date.now()) {
                return res.status(403).send({
                    message: 'ban chua dang nhap'
                });
            }

            let getUser = await userController.FindByID(result.id);
            if (!getUser) {
                return res.status(403).send({
                    message: 'ban chua dang nhap'
                });
            }

            req.userId = getUser._id;
            req.currentUser = getUser;
            next();
        } catch (error) {
            return res.status(403).send({
                message: 'ban chua dang nhap'
            });
        }
    },
    checkRole: function (...requiredRole) {
        let requiredRoleNormalized = requiredRole.map(normalizeRoleName);

        return async function (req, res, next) {
            let getUser = req.currentUser;
            if (!getUser) {
                getUser = await userController.FindByID(req.userId);
            }

            if (!getUser || !getUser.role) {
                return res.status(403).send({
                    message: 'ban khong co quyen'
                });
            }

            let roleName = normalizeRoleName(getUser.role.name || getUser.role);
            if (requiredRoleNormalized.includes(roleName)) {
                return next();
            }

            return res.status(403).send({
                message: 'ban khong co quyen'
            });
        };
    }
};
