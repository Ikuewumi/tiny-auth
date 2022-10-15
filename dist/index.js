"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const classes_1 = require("./server/classes");
const misc_1 = require("./server/misc");
/**
 * Creates a AuthInstance
 * @param props {Params.Base}
 * ### The Props Object  {
 *
 *    ```model```: The mongoose model for the user,
 *
 *    ```roles```: The roles of different users in order of their importance e.g. ```['user', 'admin', 'superadmin']```,
 *
 *    ```keys```: The environment variables to help encrypt and decrypt data as needed e.g. ```{ secretKey: XXXXXXXXX..... }```
 *
 * }
 * @returns {AuthInstance} a AuthInstance
 */
const createAuthInstance = (props) => {
    const g = (0, misc_1.getGlobalObject)();
    g.tinyAuth = classes_1.AuthInstance.instance(props);
    return g.tinyAuth;
};
/**
 * Returns the current AuthInstance
 * @param props {Params.Base}
 * ### The Props Object  {
 *
 *    ```model```: The mongoose model for the user,
 *
 *    ```roles```: The roles of different users in order of their importance e.g. ```['user', 'admin', 'superadmin']```,
 *
 *    ```keys```: The environment variables to help encrypt and decrypt data as needed e.g. ```{ secretKey: XXXXXXXXX..... }```
 *
 * }
 * @returns {AuthInstance} a AuthInstance
 */
const getAuthInstance = () => {
    return classes_1.AuthInstance.instance();
};
/**
 *@todo - Build the verification and middleware generators to implelement access-control
 *
 */
module.exports = {
    createAuthInstance,
    getAuthInstance
};
