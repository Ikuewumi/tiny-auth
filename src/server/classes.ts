import mongoose, { Document, Model, UpdateWriteOpResult } from "mongoose";
import { createError, getGlobalObject } from "./misc";
import { Params, Types, BluePrints } from "./types";
import bcrypt from "bcrypt"
import jwt, { JsonWebTokenError } from "jsonwebtoken"

export class TinyAuthError extends Error {
   constructor(msg: string) {
      super()
      this.message = msg
      this.name = 'TinyAuthError'
   }
}

export class TinyAuthInstance {
   model: Model<Types.UserObj>;
   roles: string[];
   readonly keys: Types.Keys;

   private constructor(props: Params.Base) {
      const isValid = props.model instanceof Model &&
         Array.isArray(props.roles) &&
         props.roles.length > 1 &&
         !(props.roles.find(key => typeof key !== 'string' || key.trim() <= '')) &&
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
      }
   }



   /**
    * Returns a TinyAuthInstance or creates one
    * @param props {Params.Base} 
    * @returns {TinyAuthInstance} TinyAuthInstance
    */
   static instance(props: Params.Base = {} as unknown as Params.Base): TinyAuthInstance {
      const g = getGlobalObject()

      if (g.tinyAuth) {
         return g.tinyAuth
      } else {
         const instance = new TinyAuthInstance(props)
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
      const valid = TinyAuthInstance.props.regex.email.test(email) &&
         TinyAuthInstance.props.regex.password.test(password)
      if (!valid) { return createError('Invalid Properties While creating user') }

      const emailNotUnique = await this.model.exists({ email: email.trim() })
      if (emailNotUnique) { return createError('The email already exists. Please try again with a unique email') }

      const hashedPassword = await bcrypt.hash(password, 15)
      const newUser = new this.model({
         ...object,
         email: email.trim(),
         password: hashedPassword
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
      let object: Types.Obj = {}

      if (typeof input === 'string') { object = { email: input } }
      else { object = { ...input } }

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
      let object: Types.Obj = {}

      if (typeof input === 'string') { object = { email: input } }
      else { object = { ...input } }

      const result = await this.model.updateOne(object, updateObject)

      if (!(result && result?.matchedCount)) { return createError('User not updated') }

      return result
   }

   /**
    * Deletes a user from the database
    * @param input {Params.EmailOrObject} Enter your email or a custom object
    * @returns {Promise<Types.Obj>} A deleteResult Object
    */
   async removeUser(input: Params.EmailOrObject): Promise<Types.Obj> {
      let object: Types.Obj = {}

      if (typeof input === 'string') { object = { email: input } }
      else { object = { ...input } }

      const result = await this.model.deleteOne(object)

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
      const valid = TinyAuthInstance.props.regex.email.test(email) &&
         TinyAuthInstance.props.regex.password.test(password)
      if (!valid) { return createError('Email or Password invalid') }

      const object = { email: email }

      const user = await this.model.findOne(object)
      if (!(user && user._id)) return createError('Could not find User')

      const isValidPassword = await bcrypt.compare(password, user?.password!)
      if (!isValidPassword) return createError('Invalid Credentials')

      try {

         jwt.sign({ email: user.email }, this.keys.secretKey, (err?: Error | null, token?: string) => {
            if (err) { return createError('Something went wrong') }
            return { token }
         })

      } catch (e) {

         return createError('Something went wrong')

      }

      return createError('Something went wrong')

   }


}