import { randomBytes } from 'crypto';

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

import prisma from './client';

interface ParsedToken {
  userData: {
    id: number;
  };
  iat: number;
  exp: number;
}

interface RequestWithUser extends Request {
  user: {
    id: number;
    refresh_token: string | null;
  };
  parsedToken: ParsedToken;
}

const checkUserToken = async (req: RequestWithUser, res: Response, next: NextFunction) => {
  try {
    const token = req.headers.authorization;
    if (!token) {
      return res.status(401).json({ error: 'JWT must be provided' });
    }

    const parsedToken = verifyToken(token);
    if (!parsedToken) {
      throw new Error('Invalid token');
    }

    req.parsedToken = parsedToken;

    const user = await getUserFromToken(parsedToken);
    if (!user || !user.refresh_token) {
      return res
        .status(401)
        .json({ error: 'No user found for this token or refresh token is not set' });
    }

    req.user = user;
    await updateLastLogin(user.id);

    // Set the token as a cookie
    const secret = process.env.JWT_SECRET;
    if (!secret) {
      throw new Error('JWT secret is not defined');
    }
    const cookieOptions = {
      httpOnly: true,
      maxAge: 3600000, // 1 hour
      // secure: true, // Enable this option for secure (HTTPS) connections only
    };
    const tokenCookie = jwt.sign({ userData: { id: user.id } }, secret, { expiresIn: '1h' });
    res.cookie('token', tokenCookie, cookieOptions);

  } catch (err) {
    return handleError(err as Error, res);
  }

  next();
};

const verifyToken = (token: string): ParsedToken | null => {
  if (
    typeof token !== 'string' ||
    !/^Bearer [a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+$/.test(token)
  ) {
    return null;
  }

  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error('JWT secret is not defined');
  }

  try {
    return jwt.verify(token.split(' ')[1], secret) as ParsedToken;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } catch (err: any) {
    if (err.name === 'TokenExpiredError') {
      throw new Error('Token has expired');
    }
    throw new Error('Error validating token');
  }
};

const getUserFromToken = async (
  parsedToken: ParsedToken
): Promise<{ id: number; refresh_token: string | null }> => {
  if (typeof parsedToken.userData.id !== 'number') {
    throw new Error('Invalid user ID in token');
  }

  return (await prisma.user.findFirst({
    where: {
      id: parsedToken.userData.id,
    },
    select: { id: true, refresh_token: true },
  })) as { id: number; refresh_token: string | null };
};

const updateLastLogin = async (userId: number): Promise<void> => {
  await prisma.user
    .update({
      where: { id: userId },
      data: { last_login: new Date() },
    })
    .catch((err) => {
      // eslint-disable-next-line no-console
      console.log('Error updating last login ', err);
      throw new Error('Error updating last login');
    });
};

const createRefreshToken = async (userId: number): Promise<string> => {
  const refreshToken = randomBytes(64).toString('hex');

  await prisma.user.update({
    where: { id: userId },
    data: { refresh_token: refreshToken },
  });

  return refreshToken;
};



const handleError = (err: Error, res: Response): Response => {
  console.error(err);
  if (err.message === 'Token has expired') {
    return res.status(401).json({ error: err.message });
  }
  return res.status(500).json({ error: 'Error occurred' });
};

export {
  updateLastLogin,
  checkUserToken,
  verifyToken,
  getUserFromToken,
  handleError,
  createRefreshToken
};

