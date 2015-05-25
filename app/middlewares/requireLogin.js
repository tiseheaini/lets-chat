//
// Require Login
//

'use strict';

var passport = require('passport'),
    Redis = require('ioredis'),
    redis = new Redis({ host: '127.0.0.1', port: 6379, db: 1 }),
    mongoose = require('mongoose');

function getMiddleware(fail) {
    return function(req, res, next) {
        if (req.user) {
            next();
            return;
        }

        if (req.headers && req.headers.authorization) {
            var parts = req.headers.authorization.split(' ');
            if (parts.length === 2) {
                var scheme = parts[0],
                    credentials = parts[1],
                    auth;

                if (/^Bearer$/i.test(scheme)) {
                    auth = passport.authenticate('bearer', { session: false });
                    return auth(req, res, next);
                }

                if (/^Basic$/i.test(scheme)) {
                    auth = passport.authenticate('basic', { session: false });
                    return auth(req, res, next);
                }
            }
        }

        fail(req, res);
    };
}

function getVirtualUser(){
    return function(req, res, next) {
        redis.get("session_" + req.param("session"), function(err, result){
            var json = JSON.parse(result);
            var User = mongoose.model('User');
            User.findOne({email: json.email.toLowerCase()}, function(err, result){
                if (result) {

                    req.login(result, function(err){
                        next();
                    });

                } else {
                    User.create({
                        provider: 'local',
                        username: json.u_name,
                        email: json.email,
                        displayName: json.u_name
                    }, function(err, user){

                        if (err) {
                            return res.status(500).json({
                                status: 'error',
                                message: 'Create User Error.',
                                errors: err
                            });
                        }

                        req.login(user, function(err){
                            next();
                        });
                    });
                }
            });
        })
    }
}

module.exports = getMiddleware(function(req, res) {
    res.sendStatus(401);
});

module.exports.redirect = getMiddleware(function(req, res) {
    res.redirect('/login');
});

module.exports.virtualUser = getVirtualUser();
