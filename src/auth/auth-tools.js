const jwt = require('jsonwebtoken')
const { JWT_TOKEN_EXPIRES, HASURA_GRAPHQL_JWT_SECRET } = require('../config')

module.exports = {
  generateJwtToken: function(user) {
    const user_roles = user.roles.map(role => role.slug)

    if (!user_roles.includes('user')) {
      user_roles.push('user')
    }

    return jwt.sign(
      {
        'https://hasura.io/jwt/claims': {
          'x-hasura-allowed-roles': user_roles,
          'x-hasura-default-role': 'user',
          'x-hasura-user-id': user.id.toString(),
        },
      },
      HASURA_GRAPHQL_JWT_SECRET.key,
      {
        algorithm: HASURA_GRAPHQL_JWT_SECRET.type,
        expiresIn: `${JWT_TOKEN_EXPIRES}m`,
      }
    )
  },
}
