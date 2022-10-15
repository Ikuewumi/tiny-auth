import { Document, Model } from "mongoose"
import { AuthInstance } from "./classes"
import { Request, Handler, NextFunction } from 'express'

type GlobalBase = typeof globalThis

export namespace Types {
   export interface GlobalObject extends GlobalBase {
      tinyAuth?: AuthInstance
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

   export interface UserRequest extends Request {
      userDoc?: Types.UserDocument
      user?: {
         email: string
         id: string
      }
   }

   export type CustomHandler = (req: Types.UserRequest, res: Response, next: NextFunction) => any
}

export namespace Params {
   export type Base = {
      model: Model<Types.UserObj>,
      roles: Array<string>,
      keys: Types.Keys
   }

   export type EmailOrObject = string | Types.Obj

   export interface RoleObject extends Types.Obj {
      userRole: number
   }
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