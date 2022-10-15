import { TinyAuthError } from "./classes"
import { Types } from "./types"

/**
 * Returns the global object from which you can get the tinyAuth instance
 * @returns {Types.GlobalObject} The Global Object
 */
export const getGlobalObject = (): Types.GlobalObject => {
   return global as Types.GlobalObject
}

/**
 * Creates an error
 * @param message {string}
 */
export const createError = (message: string) => {
   throw new TinyAuthError(message)
}