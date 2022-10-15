import { AuthInstance } from "./server/classes";
import { createError, getGlobalObject } from "./server/misc";
import { Params } from "./server/types";

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
const createAuthInstance = (props: Params.Base) => {
   const g = getGlobalObject()
   g.tinyAuth = AuthInstance.instance(props)

   return g.tinyAuth
}

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
const getAuthInstance = (): AuthInstance => {
   return AuthInstance.instance()
}


/**
 *@todo - Build the verification and middleware generators to implelement access-control 
 * 
 */


module.exports = {
   createAuthInstance,
   getAuthInstance
}