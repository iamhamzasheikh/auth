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


// const allowedOrigins = ['http://localhost:5173']

const allowedOrigins = [
    'http://localhost:5173',                // for local development (Vite)
    'https://auth-q44fuos0c-iamhamzasheikhs-projects.vercel.app'      // 🔹 replace with your deployed frontend URL
];


app.use(express.json());
app.use(cookieParser());
// app.use(cors({ origin: true, credentials: true }));


// 🔹 4. Configure CORS BEFORE routes
app.use(cors({
  origin: allowedOrigins,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use(cors({
    origin: allowedOrigins,
    credentials: true, // allow cookies to be sent cross-site
}));

//api endpoints
app.get('/', (req, res) => res.send('Server is Running'));
app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);
app.listen(port, () => console.log(`Server Started on PORT: ${port}`));