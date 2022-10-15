import mongoose, { Document, Model, UpdateWriteOpResult } from "mongoose";
import { createError, getGlobalObject } from "./misc";
import { Params, Types, BluePrints } from "./types";
import bcrypt from "bcrypt"
import { JsonWebTokenError, VerifyCallback, verify } from "jsonwebtoken"
import chalk from "chalk"
const jwt: any = require('jsonwebtoken')
import { Handler, Request, Response, NextFunction } from "express";


export class TinyAuthError extends Error {
   constructor(msg: string) {
      super()
      this.message = msg
      this.name = 'TinyAuthError'
      console.log(chalk.underline.red(this.message))
   }
}

export class AuthInstance {
   private model: Model<Types.UserObj>;
   private roles: string[];
   readonly keys: Types.Keys;

   private constructor(props: Params.Base) {
      const isValid = props &&
         props.model instanceof Model &&
         Array.isArray(props.roles) &&
         props.roles.length > 1 &&
         !(props.roles.find(key => typeof key !== 'string' || key.trim() === '')) &&
         props.keys?.secretKey.trim() > ''

      if (!isValid) createError('Could not create instance. Invalid options')

      this.model = props.model
      this.roles = props.roles
      this.keys = props.keys


   }

   /**
    * Static Properties
    */
   static readonly props = {
      regex: {
         email: /^([a-z\d\.]+)@([a-z\d\-]+)\.([a-z]{2,8})((\.)[a-z]{2,8})?$/,
         password: /^[\w\W]{6,}$/,
      },

      /**
       * Removes the role property
       * @param object The object
       * @returns {Types.Obj} The object, with the role property removed
       */
      processObject(object: Types.Obj): Types.Obj {
         const processedObject = { ...object }
         delete processedObject.userRole
         return processedObject
      },

      getObjectFromParams(input: Params.EmailOrObject): Types.Obj {
         const valid = typeof input === 'string' || typeof input === 'object'
         if (!valid) return createError('invalid parameters. The input must be the email or a custom object')

         let object: Types.Obj = {}
         if (typeof input === 'string') { object = { email: input } }
         else { object = { ...input } }

         return object
      }
   }



   /**
    * Returns a AuthInstance or creates one
    * @param props {Params.Base} 
    * @returns {AuthInstance} AuthInstance
    */
   static instance(props: Params.Base = {} as unknown as Params.Base): AuthInstance {
      const g = getGlobalObject()

      if (g.tinyAuth) {
         return g.tinyAuth
      } else {
         const instance = new AuthInstance(props)
         return instance
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
   async createUser(email: string, password: string, object: Types.Obj = {}): Promise<Types.UserDocument> {
      const valid = AuthInstance.props.regex.email.test(email) &&
         AuthInstance.props.regex.password.test(password)
      if (!valid) { return createError('Invalid Properties While creating user') }

      const emailNotUnique = await this.model.exists({ email: email.trim() })
      if (emailNotUnique) { return createError('The email already exists. Please try again with a unique email') }
      const hashedPassword = await bcrypt.hash(password, 15)
      const newUser = new this.model({
         ...AuthInstance.props.processObject(object),
         email: email.trim(),
         password: hashedPassword,
         userRole: 0,
      })

      const result = await newUser.save()

      return result
   }

   /**
    * Find a user fron the database
    * @param input {Params.EmailOrObject} Enter your email or a custom object
    * @returns {Promise<Types.UserDocument>} A user if successful or throws an Error
    */
   async findUser(input: Params.EmailOrObject): Promise<Types.UserDocument> {
      let object: Types.Obj = AuthInstance.props.getObjectFromParams(input)
      const result = await this.model.findOne(object)
      if (!(result && result?._id)) { return createError('Could not find User') }
      return result
   }

   /**
    * Updates a user in the database
    * @param input {Params.EmailOrObject} Enter your email or a custom object
    * @param updateObject {Types.Obj} Enter the updateObject
    * @returns {Promise<UpdateWriteOpResult>} A updateResult Object
    */
   async updateUser(input: Params.EmailOrObject, updateObject: Types.Obj): Promise<UpdateWriteOpResult> {
      let object: Types.Obj = AuthInstance.props.getObjectFromParams(input)
      const result = await this.model.updateOne(
         AuthInstance.props.processObject(object),
         AuthInstance.props.processObject(updateObject)
      )
      if (!(result && result?.modifiedCount)) { return createError('User not updated') }
      return result
   }



   /**
    * Deletes a user from the database
    * @param input {Params.EmailOrObject} Enter your email or a custom object
    * @returns {Promise<Types.Obj>} A deleteResult Object
    */
   async removeUser(input: Params.EmailOrObject): Promise<Types.Obj> {
      let object: Types.Obj = AuthInstance.props.getObjectFromParams(input)
      const result = await this.model.deleteOne(AuthInstance.props.processObject(object))
      if (!(result && result?.deletedCount)) { return createError('User not deleted') }
      return result
   }



   /**
    * Logs a user in
    * @param email{string} - Enter your email
    * @param password{string} - Enter your password. Must be at least 6 characters long
    * @returns{Promise<{token: string}>} an ACCESS_TOKEN
    */
   async logIn(email: string, password: string): Promise<{ token: string } | undefined> {
      const valid = AuthInstance.props.regex.email.test(email) &&
         AuthInstance.props.regex.password.test(password)
      if (!valid) { return createError('Email or Password invalid') }

      const object = { email: email }

      const user = await this.model.findOne(object)
      if (!(user && user._id)) return createError('Could not find User')

      const isValidPassword = await bcrypt.compare(password, user?.password!)
      if (!isValidPassword) return createError('Invalid Credentials')

      jwt.sign({ email: user.email, id: user._id }, this.keys.secretKey, (err?: Error | null, token?: string) => {
         if (err) { return createError('Something went wrong') }
         return { token }
      })

      return createError('Something went wrong')

   }





   /**
    * @private Get the index of the role to be used in other properties
    * @param value {string} The value
    * 
    * @returns {number} the index of the role or throws an error
    */
   private getRoleIndex(value: string): number {
      if (!this.roles.includes(value)) return createError('This role is not part of the registered roles')
      return (this.roles.findIndex(role => role === value))
   }






   /**
    * @private Get the object of the role to be used in database operations
    * @param role {string} The role
    * 
    * @returns {Params.RoleObject} the role object 
    */
   private getRoleObject(role: string): Params.RoleObject {
      const index = this.getRoleIndex(role)

      return {
         userRole: index
      }
   }




   /**
    * @private Removes a role from a user
    * @param object {Params.EmailOrObject} Either an email or custom object of user
    * @param role {string} The role
    * 
    * @returns {Promise<UpdateWriteOpResult>} A updateResult Object
    */
   private async removeRole(object: Params.EmailOrObject, role: string): Promise<UpdateWriteOpResult> {
      const obj = AuthInstance.props.processObject({
         ...AuthInstance.props.getObjectFromParams(object),
         ...this.getRoleObject(role)
      })

      const result = await this.model.updateOne(obj, { $set: { userRole: 0 } })
      if (!(result && result?.modifiedCount)) { return createError('Role not removed') }

      return result
   }

   /**
    * @private Add a role to a user
    * @param object {Params.EmailOrObject} Either an email or custom object of user
    * @param role {string} The role
    * 
    * @returns {Promise<UpdateWriteOpResult>} A updateResult Object
    */
   private async addRole(object: Params.EmailOrObject, role: string): Promise<UpdateWriteOpResult> {
      const obj = AuthInstance.props.processObject({
         ...AuthInstance.props.getObjectFromParams(object)
      })

      const result = await this.model.updateOne(obj, { $set: this.getRoleObject(role) })
      if (!(result && result?.modifiedCount)) { return createError('Role not added') }

      return result
   }




   /**
    * Get an express middleware function to verify for different roles
    * 
    * @param role {string} The role of the middleware
    * @returns {Handler} An Express Middleware function that loads the userDocument into the request variable as ```req.userDoc```
    */
   getVerificationMiddleware(role: string): Handler {

      const roleIndex = this.getRoleIndex(role)


      const middleWare = (req: Types.UserRequest, res: Response, next: NextFunction) => {
         try {
            const isPresent =
               req.headers['authorization'] &&
               req.headers['authorization'] > 'Bearer ' &&
               req.headers['authorization'].split(' ')[1] > ''
            if (!isPresent) return sendMsg('The token is invalid', 401)

            const token = req.headers['authorization']!.split(' ')[1]

            jwt.verify(
               token, this.keys.secretKey,
               async (err: Error | null, decoded: { email: string, id: string }) => {
                  if (err) return sendMsg('Forbidden', 403)

                  const userIsValid = await this.model.findOne({
                     email: decoded?.email ?? '',
                     id: decoded?.id ?? '',
                     userRole: { $gte: roleIndex }
                  })

                  if (!(userIsValid && userIsValid._id)) return sendMsg('Invalid Credentials', 403)

                  req.userDoc = userIsValid
                  req.user = {
                     email: decoded.email,
                     id: decoded.id
                  }

                  next()
               }
            )


            /**
             * Sends an error message to the client
             * @param msg {string} The message to be sent
             * @param code {number} The Error code. Default(400)
             * @returns {void}  
             */
            function sendMsg(msg: string, code: number = 400): void {
               res.status(code).json({ msg })
            }

         }
         catch (e) { return createError(String(e)) }
      }

      return middleWare

   }

}