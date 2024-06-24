
import express, { Router, Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

import { createRefreshToken, updateLastLogin } from '../middleware/authentication';
import prisma from "../middleware/client";
import { hashPassword, verifyPassword } from '../middleware/hash';

interface ParsedToken {
  userData: {
    id: number;
  };
  iat: number;
  exp: number;
}

const userRouter: Router = express.Router();

const sayHelloUser = (req: Request, res: Response) => {
  res.json({ message: 'Hello user' });
};

const registerUser = async (req: Request, res: Response) => {
  const { firstName, lastName, email, password } = req.body;
  try {
    const { salt, hashedPassword } = hashPassword(password);
    const user = await prisma.user.create({
      data: {
        first_name: firstName,
        last_name: lastName,
        email,
        password: hashedPassword,
        salt: salt,
      },
    });
    res.json({
      message: 'User created',
      user: {
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email,
      },
    });
  } catch (error) {
    res.json({ message: 'User not created' });
  }
};

const refreshToken = async (req: Request, res: Response) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token not found' });
  }

  try {
    const user = await prisma.user.findFirst({
      where: {
        refresh_token: refreshToken,
      },
      select: { id: true },
    });

    if (user) {
      const secret = process.env.JWT_SECRET;
      if (!secret) {
        throw new Error('JWT secret is not defined');
      }

      // Generate a new JWT token
      const token = jwt.sign({ userData: { id: user.id, timestamp: new Date().getTime() } }, secret, { expiresIn: '1h' });

      // Generate a new refresh token and update it in the database
      const newRefreshToken = await createRefreshToken(user.id);

      // Update the cookies with the new tokens
      res
        .cookie('token', token, { httpOnly: true, maxAge: 3600000 })
        .cookie('refreshToken', newRefreshToken, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 })
        .json({ message: 'New token issued', token });
    } else {
      console.info('Invalid refresh token');
      res.status(401).json({ message: 'Invalid refresh token' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Something went wrong', error });
  }
};

// Add the refresh token route
userRouter.post('/refresh_token', refreshToken);


const loginUser = async (req: Request, res: Response) => {
  const { email, password } = req.body;
  try {
    const user = await prisma.user.findUnique({
      where: {
        email,
      },
      select: { id: true, salt: true, password: true },
    });
    if (user && user.salt && user.password) {
      if (verifyPassword(password, user.password, user.salt)) {
        const secret = process.env.JWT_SECRET;
        if (!secret) {
          throw new Error('JWT secret is not defined');
        }
        const token = jwt.sign({ userData: { id: user.id, timestamp: new Date().getTime() } }, secret, { expiresIn: '1h' });
        const refreshToken = await createRefreshToken(user.id);
        await updateLastLogin(user.id);

        res
          .cookie('token', token, { httpOnly: true, maxAge: 3600000 }) // Set the token as an HTTP-only cookie
          .cookie('refreshToken', refreshToken, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 }) // Set the refreshToken as an HTTP-only cookie
          .json({ message: 'User logged in', token, refreshToken });
      } else {
        console.info('Wrong password');
        res.status(401).json({ message: 'Wrong password' });
      }
    } else {
      console.info('User not found');
      res.status(404).json({ message: 'User not found' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Something went wrong', error });
  }
};


// Middleware function to verify the token
const verifyToken = (req: any, res: Response, next: NextFunction) => {
  const token = req.cookies.token; // Access the token from the "token" cookie
  console.info("token was ", token)

  if (!token) {
    return res.status(401).json({ error: 'Token not found' });
  }

  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error('JWT secret is not defined');
  }

  try {
    const parsedToken = jwt.verify(token, secret) as ParsedToken;
    req.parsedToken = parsedToken; // Store the parsed token in the request object for later use
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

const someProtectedRouteHandler = (req: any, res: Response) => {
  // Access the parsedToken from the request object
  const parsedToken = req.parsedToken;

  // Access the user ID from the parsedToken
  const userId = parsedToken?.userData.id;

  // Perform actions specific to the protected route
  // ...

  // Send a response
  res.json({ message: 'Protected route accessed successfully', userId });
};

// Define the routes
userRouter.get('/', sayHelloUser);
userRouter.get('/safeHello', verifyToken, sayHelloUser)
userRouter.post('/', registerUser);
userRouter.post('/login', loginUser);
userRouter.get('/verify', verifyToken, someProtectedRouteHandler);

export default userRouter;

