type GlobalBase = typeof globalThis

export namespace Types {
   export interface GlobalObject extends GlobalBase {
      tinyAuth?: {

      }
   }

   export type Keys = {
      secretKey: string
   }
}