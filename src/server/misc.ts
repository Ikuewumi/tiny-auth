import { Types } from "./types"

/**
 * 
 * @returns {Types.GlobalObject}
 */
export const getGlobalObject = (): Types.GlobalObject => {
   return global as Types.GlobalObject
}