import cookieParser from 'cookie-parser'; // Import the cookie-parser middleware
import cors from 'cors';
import express from 'express';
import helmet from 'helmet';

import userRouter from './routes/userRouter';

const app = express();
const port = process.env.PORT || 3000;

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use('/user', userRouter);

app.get('/health', (req, res) => {
  res.json({
    status: 'UP',
    timestamp: Date.now()
  });
});

app.listen(port, () => {
  console.info();
});
