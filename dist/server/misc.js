"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createError = exports.getGlobalObject = void 0;
const classes_1 = require("./classes");
/**
 * Returns the global object from which you can get the tinyAuth instance
 * @returns {Types.GlobalObject} The Global Object
 */
const getGlobalObject = () => {
    return global;
};
exports.getGlobalObject = getGlobalObject;
/**
 * Creates an error
 * @param message {string}
 */
const createError = (message) => {
    throw new classes_1.TinyAuthError(message);
};
exports.createError = createError;
