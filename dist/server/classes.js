"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthInstance = exports.TinyAuthError = void 0;
const mongoose_1 = require("mongoose");
const misc_1 = require("./misc");
const bcrypt_1 = __importDefault(require("bcrypt"));
const chalk_1 = __importDefault(require("chalk"));
const jwt = require('jsonwebtoken');
class TinyAuthError extends Error {
    constructor(msg) {
        super();
        this.message = msg;
        this.name = 'TinyAuthError';
        console.log(chalk_1.default.underline.red(this.message));
    }
}
exports.TinyAuthError = TinyAuthError;
class AuthInstance {
    constructor(props) {
        var _a;
        const isValid = props &&
            props.model instanceof mongoose_1.Model &&
            Array.isArray(props.roles) &&
            props.roles.length > 1 &&
            !(props.roles.find(key => typeof key !== 'string' || key.trim() === '')) &&
            ((_a = props.keys) === null || _a === void 0 ? void 0 : _a.secretKey.trim()) > '';
        if (!isValid)
            (0, misc_1.createError)('Could not create instance. Invalid options');
        this.model = props.model;
        this.roles = props.roles;
        this.keys = props.keys;
    }
    /**
     * Returns a AuthInstance or creates one
     * @param props {Params.Base}
     * @returns {AuthInstance} AuthInstance
     */
    static instance(props = {}) {
        const g = (0, misc_1.getGlobalObject)();
        if (g.tinyAuth) {
            return g.tinyAuth;
        }
        else {
            const instance = new AuthInstance(props);
            return instance;
        }
    }
    /**
     * Creates a new user
     * @param email {string} Enter your email. Must be a unique email
     * @param password {string} Enter your password. It must be at least 6 characters long
     * @param object {Types.Obj} Any extra properties to be added
     *
     * @returns {Promise<Types.UserDocument>} A new user if successful or throws an Error
     */
    createUser(email, password, object = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            const valid = AuthInstance.props.regex.email.test(email) &&
                AuthInstance.props.regex.password.test(password);
            if (!valid) {
                return (0, misc_1.createError)('Invalid Properties While creating user');
            }
            const emailNotUnique = yield this.model.exists({ email: email.trim() });
            if (emailNotUnique) {
                return (0, misc_1.createError)('The email already exists. Please try again with a unique email');
            }
            const hashedPassword = yield bcrypt_1.default.hash(password, 15);
            const newUser = new this.model(Object.assign(Object.assign({}, AuthInstance.props.processObject(object)), { email: email.trim(), password: hashedPassword, userRole: 0 }));
            const result = yield newUser.save();
            return result;
        });
    }
    /**
     * Find a user fron the database
     * @param input {Params.EmailOrObject} Enter your email or a custom object
     * @returns {Promise<Types.UserDocument>} A user if successful or throws an Error
     */
    findUser(input) {
        return __awaiter(this, void 0, void 0, function* () {
            let object = AuthInstance.props.getObjectFromParams(input);
            const result = yield this.model.findOne(object);
            if (!(result && (result === null || result === void 0 ? void 0 : result._id))) {
                return (0, misc_1.createError)('Could not find User');
            }
            return result;
        });
    }
    /**
     * Updates a user in the database
     * @param input {Params.EmailOrObject} Enter your email or a custom object
     * @param updateObject {Types.Obj} Enter the updateObject
     * @returns {Promise<UpdateWriteOpResult>} A updateResult Object
     */
    updateUser(input, updateObject) {
        return __awaiter(this, void 0, void 0, function* () {
            let object = AuthInstance.props.getObjectFromParams(input);
            const result = yield this.model.updateOne(AuthInstance.props.processObject(object), AuthInstance.props.processObject(updateObject));
            if (!(result && (result === null || result === void 0 ? void 0 : result.modifiedCount))) {
                return (0, misc_1.createError)('User not updated');
            }
            return result;
        });
    }
    /**
     * Deletes a user from the database
     * @param input {Params.EmailOrObject} Enter your email or a custom object
     * @returns {Promise<Types.Obj>} A deleteResult Object
     */
    removeUser(input) {
        return __awaiter(this, void 0, void 0, function* () {
            let object = AuthInstance.props.getObjectFromParams(input);
            const result = yield this.model.deleteOne(AuthInstance.props.processObject(object));
            if (!(result && (result === null || result === void 0 ? void 0 : result.deletedCount))) {
                return (0, misc_1.createError)('User not deleted');
            }
            return result;
        });
    }
    /**
     * Logs a user in
     * @param email{string} - Enter your email
     * @param password{string} - Enter your password. Must be at least 6 characters long
     * @returns{Promise<{token: string}>} an ACCESS_TOKEN
     */
    logIn(email, password) {
        return __awaiter(this, void 0, void 0, function* () {
            const valid = AuthInstance.props.regex.email.test(email) &&
                AuthInstance.props.regex.password.test(password);
            if (!valid) {
                return (0, misc_1.createError)('Email or Password invalid');
            }
            const object = { email: email };
            const user = yield this.model.findOne(object);
            if (!(user && user._id))
                return (0, misc_1.createError)('Could not find User');
            const isValidPassword = yield bcrypt_1.default.compare(password, user === null || user === void 0 ? void 0 : user.password);
            if (!isValidPassword)
                return (0, misc_1.createError)('Invalid Credentials');
            jwt.sign({ email: user.email, id: user._id }, this.keys.secretKey, (err, token) => {
                if (err) {
                    return (0, misc_1.createError)('Something went wrong');
                }
                return { token };
            });
            return (0, misc_1.createError)('Something went wrong');
        });
    }
    /**
     * @private Get the index of the role to be used in other properties
     * @param value {string} The value
     *
     * @returns {number} the index of the role or throws an error
     */
    getRoleIndex(value) {
        if (!this.roles.includes(value))
            return (0, misc_1.createError)('This role is not part of the registered roles');
        return (this.roles.findIndex(role => role === value));
    }
    /**
     * @private Get the object of the role to be used in database operations
     * @param role {string} The role
     *
     * @returns {Params.RoleObject} the role object
     */
    getRoleObject(role) {
        const index = this.getRoleIndex(role);
        return {
            userRole: index
        };
    }
    /**
     * @private Removes a role from a user
     * @param object {Params.EmailOrObject} Either an email or custom object of user
     * @param role {string} The role
     *
     * @returns {Promise<UpdateWriteOpResult>} A updateResult Object
     */
    removeRole(object, role) {
        return __awaiter(this, void 0, void 0, function* () {
            const obj = AuthInstance.props.processObject(Object.assign(Object.assign({}, AuthInstance.props.getObjectFromParams(object)), this.getRoleObject(role)));
            const result = yield this.model.updateOne(obj, { $set: { userRole: 0 } });
            if (!(result && (result === null || result === void 0 ? void 0 : result.modifiedCount))) {
                return (0, misc_1.createError)('Role not removed');
            }
            return result;
        });
    }
    /**
     * @private Add a role to a user
     * @param object {Params.EmailOrObject} Either an email or custom object of user
     * @param role {string} The role
     *
     * @returns {Promise<UpdateWriteOpResult>} A updateResult Object
     */
    addRole(object, role) {
        return __awaiter(this, void 0, void 0, function* () {
            const obj = AuthInstance.props.processObject(Object.assign({}, AuthInstance.props.getObjectFromParams(object)));
            const result = yield this.model.updateOne(obj, { $set: this.getRoleObject(role) });
            if (!(result && (result === null || result === void 0 ? void 0 : result.modifiedCount))) {
                return (0, misc_1.createError)('Role not added');
            }
            return result;
        });
    }
    /**
     * Get an express middleware function to verify for different roles
     *
     * @param role {string} The role of the middleware
     * @returns {Handler} An Express Middleware function that loads the userDocument into the request variable as ```req.userDoc```
     */
    getVerificationMiddleware(role) {
        const roleIndex = this.getRoleIndex(role);
        const middleWare = (req, res, next) => {
            try {
                const isPresent = req.headers['authorization'] &&
                    req.headers['authorization'] > 'Bearer ' &&
                    req.headers['authorization'].split(' ')[1] > '';
                if (!isPresent)
                    return sendMsg('The token is invalid', 401);
                const token = req.headers['authorization'].split(' ')[1];
                jwt.verify(token, this.keys.secretKey, (err, decoded) => __awaiter(this, void 0, void 0, function* () {
                    var _a, _b;
                    if (err)
                        return sendMsg('Forbidden', 403);
                    const userIsValid = yield this.model.findOne({
                        email: (_a = decoded === null || decoded === void 0 ? void 0 : decoded.email) !== null && _a !== void 0 ? _a : '',
                        id: (_b = decoded === null || decoded === void 0 ? void 0 : decoded.id) !== null && _b !== void 0 ? _b : '',
                        userRole: { $gte: roleIndex }
                    });
                    if (!(userIsValid && userIsValid._id))
                        return sendMsg('Invalid Credentials', 403);
                    req.userDoc = userIsValid;
                    req.user = {
                        email: decoded.email,
                        id: decoded.id
                    };
                    next();
                }));
                /**
                 * Sends an error message to the client
                 * @param msg {string} The message to be sent
                 * @param code {number} The Error code. Default(400)
                 * @returns {void}
                 */
                function sendMsg(msg, code = 400) {
                    res.status(code).json({ msg });
                }
            }
            catch (e) {
                return (0, misc_1.createError)(String(e));
            }
        };
        return middleWare;
    }
}
exports.AuthInstance = AuthInstance;
/**
 * Static Properties
 */
AuthInstance.props = {
    regex: {
        email: /^([a-z\d\.]+)@([a-z\d\-]+)\.([a-z]{2,8})((\.)[a-z]{2,8})?$/,
        password: /^[\w\W]{6,}$/,
    },
    /**
     * Removes the role property
     * @param object The object
     * @returns {Types.Obj} The object, with the role property removed
     */
    processObject(object) {
        const processedObject = Object.assign({}, object);
        delete processedObject.userRole;
        return processedObject;
    },
    getObjectFromParams(input) {
        const valid = typeof input === 'string' || typeof input === 'object';
        if (!valid)
            return (0, misc_1.createError)('invalid parameters. The input must be the email or a custom object');
        let object = {};
        if (typeof input === 'string') {
            object = { email: input };
        }
        else {
            object = Object.assign({}, input);
        }
        return object;
    }
};
