import express from 'express';
import cors from 'cors';
import 'dotenv/config';
import cookieParser from 'cookie-parser';
import connectDB from './Config/MongoDB.js';
import authRouter from './Routes/authRoutes.js';
import userRouter from './Routes/userRoutes.js';



const app = express();
const port = process.env.PORT || 4000;
connectDB();


const allowedOrigins = ['http://localhost:5173']

app.use(express.json());
app.use(cookieParser());
app.use(cors({origin: allowedOrigins,  credentials: true }));

//api endpoints
app.get('/', (req, res) => res.send('Server is Live'))
app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);
app.listen(port, () => console.log(`Server Started on PORT: ${port}`));