import { Document, Model } from "mongoose"
import { TinyAuthInstance } from "./classes"

type GlobalBase = typeof globalThis

export namespace Types {
   export interface GlobalObject extends GlobalBase {
      tinyAuth?: TinyAuthInstance
   }

   export type Keys = {
      secretKey: string
   }

   export type Obj = {
      [index: string]: any
   }

   export interface UserObj extends Types.Obj {
      email: string
      password: string
   }

   export type UserDocument = Document<unknown, any, Types.UserObj>
}

export namespace Params {
   export type Base = {
      model: Model<Types.UserObj>,
      roles: Array<string>,
      keys: Types.Keys
   }

   export type EmailOrObject = string | Types.Obj
}

export namespace BluePrints {
   export interface Class {
      findUser: (object: { [index: string]: any }) => (Document<{ [index: string]: any }>),
      createUser: (object: { [index: string]: any }, email: string, password: string) => (Document<{ [index: string]: any }>),
      removeUser: (object: { [index: string]: any }) => (number)

      /**
       * Logs a user in
       * @param email{string} - Enter your email
       * @param password{string} - Enter your password. Must be at least 6 characters long
       * @returns{{token: string}} an ACCESS_TOKEN
       */
      logIn: (email: string, password: string) => ({
         token: string
      }),


      [index: string]: any
   }
}