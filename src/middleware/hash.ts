import crypto from 'crypto';

interface IHashedPassword {
  salt: string;
  hashedPassword: string;
}

const hashPassword = (password: string, salt = crypto.randomBytes(16).toString('hex')): IHashedPassword => {
  const hashedPassword = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return { salt, hashedPassword };
}

const verifyPassword = (password: string, hashedPassword: string, salt: string): boolean => {
  const passwordData = hashPassword(password, salt);
  return passwordData.hashedPassword === hashedPassword;
}

export {
  hashPassword,
  verifyPassword
}

