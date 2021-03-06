const express = require('express')
const Joi = require('joi')
const Boom = require('boom')
const bcrypt = require('bcryptjs')
const uuidv4 = require('uuid/v4')
const { graphql_client } = require('../graphql-client')

const {
  USER_REGISTRATION_AUTO_ACTIVE,
  USER_MANAGEMENT_DATABASE_SCHEMA_NAME,
  REFETCH_TOKEN_EXPIRES,
  JWT_TOKEN_EXPIRES,
} = require('../config')

const auth_tools = require('./auth-tools')

let router = express.Router()

const schema_name =
  USER_MANAGEMENT_DATABASE_SCHEMA_NAME === 'public'
    ? ''
    : USER_MANAGEMENT_DATABASE_SCHEMA_NAME.toString().toLowerCase() + '_'

router.post('/register', async (req, res, next) => {
  let hasura_data
  let password_hash

  const schema = Joi.object().keys({
    username: Joi.string().required(),
    password: Joi.string().required(),
  })

  const { error, value } = schema.validate(req.body)

  if (error) {
    return next(Boom.badRequest(error.details[0].message))
  }

  const { username, password } = value

  // check for duplicates
  let query = `
  query (
    $username: String!
  ) {
    ${schema_name}users (
      where: {
        username: { _eq: $username }
      }
    ) {
      id
    }
  }
  `

  try {
    hasura_data = await graphql_client.request(query, {
      username,
    })
  } catch (e) {
    console.error(e)
    return next(
      Boom.badImplementation("Unable to check for 'username' duplication")
    )
  }

  if (hasura_data[`${schema_name}users`].length !== 0) {
    return next(Boom.unauthorized("The 'username' is already exist"))
  }

  // generate password_hash
  try {
    password_hash = await bcrypt.hash(password, 10)
  } catch (e) {
    console.error(e)
    return next(Boom.badImplementation("Unable to generate 'password hash'"))
  }

  // insert user
  query = `
  mutation (
    $user: ${schema_name}users_insert_input!
  ) {
    insert_${schema_name}users(
      objects: [$user]
    ) {
      affected_rows
    }
  }
  `

  try {
    await graphql_client.request(query, {
      user: {
        username,
        password: password_hash,
        secret_token: uuidv4(),
        active: USER_REGISTRATION_AUTO_ACTIVE,
      },
    })
  } catch (e) {
    console.error(e)
    return next(Boom.badImplementation('Unable to create user.'))
  }

  res.send('OK')
})

router.post('/activate-account', async (req, res, next) => {
  let hasura_data

  const schema = Joi.object().keys({
    secret_token: Joi.string()
      .uuid({ version: ['uuidv4'] })
      .required(),
  })

  const { error, value } = schema.validate(req.body)

  if (error) {
    return next(Boom.badRequest(error.details[0].message))
  }

  const { secret_token } = value

  const query = `
  mutation activate_account (
    $secret_token: uuid!
    $new_secret_token: uuid!
  ) {
    update_${schema_name}users (
      where: {
        _and: [
          {
            secret_token: { _eq: $secret_token}
          },{
            active: { _eq: false}
          }
        ]
      }
      _set: {
        active: true,
        secret_token: $new_secret_token,
      }
    ) {
      affected_rows
    }
  }
  `

  try {
    hasura_data = await graphql_client.request(query, {
      secret_token,
      new_secret_token: uuidv4(),
    })
  } catch (e) {
    console.error(e)
    return next(Boom.unauthorized('Unable to find account for activation.'))
  }

  if (hasura_data[`update_${schema_name}users`].affected_rows === 0) {
    // console.error('Account already activated');
    return next(
      Boom.unauthorized('Account is already activated or there is no account.')
    )
  }

  res.send('OK')
})

router.post('/new-password', async (req, res, next) => {
  let hasura_data
  let password_hash

  const schema = Joi.object().keys({
    secret_token: Joi.string()
      .uuid({ version: ['uuidv4'] })
      .required(),
    password: Joi.string().required(),
  })

  const { error, value } = schema.validate(req.body)

  if (error) {
    return next(Boom.badRequest(error.details[0].message))
  }

  const { secret_token, password } = value

  // update password and username activation token
  try {
    password_hash = await bcrypt.hash(password, 10)
  } catch (e) {
    console.error(e)
    return next(Boom.badImplementation(`Unable to generate 'password_hash'`))
  }

  const query = `
  mutation  (
    $secret_token: uuid!,
    $password_hash: String!,
    $new_secret_token: uuid!
  ) {
    update_${schema_name}users (
      where: {
        secret_token: { _eq: $secret_token}
      }
      _set: {
        password: $password_hash,
        secret_token: $new_secret_token
      }
    ) {
      affected_rows
    }
  }
  `

  try {
    const new_secret_token = uuidv4()
    hasura_data = await graphql_client.request(query, {
      secret_token,
      password_hash,
      new_secret_token,
    })
  } catch (e) {
    console.error(e)
    return next(Boom.unauthorized(`Unable to update 'password'`))
  }

  if (hasura.update_users.affected_rows === 0) {
    console.log('0 affected rows')
    return next(Boom.badImplementation(`Unable to update password for user`))
  }

  // return 200 OK
  res.send('OK')
})

router.post('/login', async (req, res, next) => {
  // validate username and password
  const schema = Joi.object().keys({
    email: Joi.string().required(),
    password: Joi.string().required(),
  })

  const { error, value } = schema.validate(req.body)

  if (error) {
    return next(Boom.badRequest(error.details[0].message))
  }

  const { email, password } = value

  let query = `
  query (
    $email: String!
  ) {
    a2_users (
      where: {
        email: { _eq: $email}
      }
    ) {
      id
      password
      active
      roles {
        role{
          slug
        }
      }
    }
  }
  `

  let hasura_data
  try {
    hasura_data = await graphql_client.request(query, {
      email,
    })
  } catch (e) {
    console.error(e)
    // console.error('Error connection to GraphQL');
    return next(Boom.unauthorized("Unable to find 'user'"))
  }

  if (hasura_data[`a2_users`].length === 0) {
    // console.error("No user with this 'username'");
    return next(Boom.unauthorized("Invalid 'email' or 'password'"))
  }

  // check if we got any user back
  const userRaw = hasura_data[`a2_users`][0]
  const roles = userRaw.roles.map(r => r.role.slug)
  const user = {
    ...userRaw,
    roles,
  }
  if (!user.active) {
    // console.error('User not activated');
    return next(Boom.unauthorized('User not activated.'))
  }

  // see if password hashes matches
  const match = await bcrypt.compare(password, user.password)

  if (!match) {
    console.error('Password does not match')
    return next(Boom.unauthorized("Invalid 'email' or 'password'"))
  }
  console.warn('user: ' + JSON.stringify(user, null, 2))

  const jwt_token = auth_tools.generateJwtToken(user)

  // generate refetch token and put in database
  query = `
  mutation (
    $refetch_token_data: a2_jwt_tokens_insert_input!
  ) {
    insert_a2_jwt_tokens(
      objects: [$refetch_token_data]
    ) {
        affected_rows
      }
    }
  `

  const refetch_token = uuidv4()
  try {
    await graphql_client.request(query, {
      refetch_token_data: {
        userId: user.id,
        refetch_token: refetch_token,
        expiresAt: new Date(
          new Date().getTime() + REFETCH_TOKEN_EXPIRES * 60 * 1000
        ), // convert from minutes to milli seconds
      },
    })
  } catch (e) {
    console.error(e)
    return next(
      Boom.badImplementation("Could not update 'refetch token' for user")
    )
  }

  res.cookie('jwt_token', jwt_token, {
    maxAge: JWT_TOKEN_EXPIRES * 60 * 1000, // convert from minute to milliseconds
    httpOnly: true,
  })

  // return jwt token and refetch token to client
  res.json({
    jwt_token,
    refetch_token,
    userId: user.id,
  })
})

router.post('/refetch-token', async (req, res, next) => {
  // validate username and password
  const schema = Joi.object().keys({
    refetch_token: Joi.string().required(),
    userId: Joi.required(),
  })

  const { error, value } = schema.validate(req.body)

  if (error) {
    return next(Boom.badRequest(error.details[0].message))
  }

  const { refetch_token, userId } = value

  let query = `
  query get_refetch_token(
    $refetch_token: uuid!,
    $userId: uuid!
    $current_timestampz: timestamp!,
  ) {
  a2_jwt_tokens (
      where: {
        _and: [{
          refetch_token: { _eq: $refetch_token }
        }, {
          userId: { _eq: $userId }
        }, {
          user: { active: { _eq: true }}
        }, {
          expiresAt: { _gte: $current_timestampz }
        }]
      }
    ) {
      user {
        id
        active
        roles {
          role{
            slug
          }
        }
      }
    }
  }
  `

  let hasura_data
  try {
    hasura_data = await graphql_client.request(query, {
      refetch_token,
      userId,
      current_timestampz: new Date(),
    })
  } catch (e) {
    console.error(e)
    // console.error('Error connection to GraphQL');
    return next(Boom.unauthorized("Invalid 'a2_jwt_tokens' or 'userId'"))
  }

  if (hasura_data[`a2_jwt_tokens`].length === 0) {
    // console.error('Incorrect user id or refetch token');
    return next(Boom.unauthorized("Invalid 'a2_jwt_tokens' or 'userId'"))
  }

  const user = hasura_data[`a2_jwt_tokens`][0].user

  // delete current refetch token and generate a new, and insert the
  // new refetch_token in the database
  // two mutations as transaction
  query = `
  mutation (
    $old_a2_jwt_tokens: uuid!,
    $new_refetch_token_data: a2_jwt_tokens_insert_input!
    $userId: uuid!
  ) {
    delete_a2_jwt_tokens (
      where: {
        _and: [{
          refetch_token: { _eq: $old_a2_jwt_tokens }
        }, {
          userId: { _eq: $userId }
        }]
      }
    ) {
      affected_rows
    }
    insert_a2_jwt_tokens (
      objects: [$new_refetch_token_data]
    ) {
      affected_rows
    }
  }
  `

  const new_refetch_token = uuidv4()
  try {
    await graphql_client.request(query, {
      old_a2_jwt_tokens: refetch_token,
      new_refetch_token_data: {
        userId: userId,
        refetch_token: new_refetch_token,
        expiresAt: new Date(
          new Date().getTime() + REFETCH_TOKEN_EXPIRES * 60 * 1000
        ), // convert from minutes to milli seconds
      },
      userId,
    })
  } catch (e) {
    console.error(e)
    // console.error('unable to create new refetch token and delete old');
    return next(Boom.unauthorized("Invalid 'a2_jwt_tokens' or 'userId'"))
  }

  // generate new jwt token
  const jwt_token = auth_tools.generateJwtToken(user)

  res.cookie('jwt_token', jwt_token, {
    maxAge: JWT_TOKEN_EXPIRES * 60 * 1000,
    httpOnly: true,
  })

  res.json({
    jwt_token,
    refetch_token: new_refetch_token,
    userId,
  })
})

module.exports = router
