import { findUserById } from './db.js';

export async function findAccount(_ctx, id) {
  const user = findUserById(id);
  if (!user) return undefined;

  return {
    accountId: user.id,
    async claims(_use, scope) {
      const claims = { sub: user.id };
      if (scope.includes('profile')) {
        claims.preferred_username = user.username;
        if (user.picture) claims.picture = user.picture;
      }
      if (scope.includes('email') && user.email) claims.email = user.email;
      return claims;
    },
  };
}
