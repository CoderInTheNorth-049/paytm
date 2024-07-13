const JWT_SECRET = require("./config");
const jwt = require('jsonwebtoken');

const authMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if(!authHeader){
        return res.status(403).json({
            message: "Authorization failed (No Authorization header)"
        });
    }
    else if(!authHeader.startsWith('Bearer ')){
        return res.status(403).json({
            message: "Authorization failed (Authorization header not starts with Bearer)"
        });
    }
    const token = authHeader.split(' ')[1];

    try{
        const decoded = jwt.verify(token, JWT_SECRET);
        if(decoded.userId){
            req.userId = decoded.userId;
            next();
        } else {
            return res.status(403).json({
                message: "Authorization failed due to wrong token"
            });
        }
    } catch (err){
        return res.status(403).json({
            message: "Authorization failed due to error"
        });
    }
}

module.exports = {
    authMiddleware
}