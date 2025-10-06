import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken'
import userModel from '../Models/userModel.js'
import transporter from '../Config/nodeMailer.js';

// we make scheme for user register

export const register = async (req, res) => {
    const { name, email, password } = req.body;

    if (!email || !password || !name) {
        return res.json({ msg: 'Please enter all fields' });
    }

    try {

        const existingUser = await userModel.findOne({ email })

        if (existingUser) {
            return res.json({ Success: false, message: 'User with this Email already exists' });
        }
        // now we store user password in encrypted form

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new userModel(
            {
                name: name,
                email: email,
                password: hashedPassword
            }
        );
        await user.save();

        // const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET.trim(), { expiresIn: '7d' });

        res.cookie('token', token,
            {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
                expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
            }
        );

        //sending welcome email notification

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome to auth',
            text: `Welcome, ${name}, Your Account has been Created with Email Id: ${email}`

        }; await transporter.sendMail(mailOptions);
        console.log('Mail Options:', mailOptions);

        return res.json({ Success: true })
    }
    catch (error) {
        res.json({ Success: false, message: error.message })
    }
}
// now we make user login request
export const login = async (req, res) => {
    const { email, password } = req.body;

    // Validate email and password fields
    if (!email) {
        return res.status(400).json({ Success: false, msg: 'Please enter your email address' });
    }
    if (!password) {
        return res.status(400).json({ Success: false, msg: 'Please enter your password' });
    }

    try {
        // Find the user by email
        const user = await userModel.findOne({ email });

        if (!user) {
            // Avoid exposing whether the user exists
            return res.status(401).json({ Success: false, message: 'Invalid email or password' });
        }

        // Compare the provided password with the hashed password in the database
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ Success: false, message: 'Invalid email or password' });
        }

        // Generate a JWT token
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET.trim(), { expiresIn: '7d' });

        // Set the token as an HTTP-only cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
        });

        // Respond with success and optionally user data
        return res.status(200).json({ Success: true, message: 'Login successful', token });

    } catch (error) {
        // Catch and handle any errors
        return res.status(500).json({ Success: false, message: 'An error occurred. Please try again.' });
    }
};


export const logout = async (req, res) => {
    try {
        console.log('Logout request received');

        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        });

        console.log('Cookie cleared successfully', req.cookies.token);
        return res.status(200).json({
            success: true,
            message: 'Logged out successfully'
        });
    } catch (error) {
        console.error('Logout error:', error);
        return res.status(500).json({
            success: false,
            message: error.message || 'Failed to logout'
        });
    }
}

// now we can account verification using email otp 

export const sendVerifyOtp = async (req, res) => {
    try {

        const { userId } = req.body;

        const user = await userModel.findById(userId);

        if (user.isAccountVerified) {
            return res.json({ Success: false, message: 'Account is already verified' });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000;

        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP',
            text: `Your Account Verification Code is: ${otp}`,
        };

        await transporter.sendMail(mailOptions);
        res.json({ Success: true, message: 'Verification Otp Sent on Email' })

    } catch (error) {
        res.json({ Success: false, message: error.message })
    }
}

/// now we verify account using email verification otp

export const verifyEmail = async (req, res) => {
    const { userId, otp } = req.body;

    if (!userId || !otp) {
        return res.json({ Success: false, message: 'Missing Details' });
    }

    try {

        const user = await userModel.findById(userId);

        if (!user) {
            return res.json({ Success: false, message: 'User not found' });
        }

        if (user.verifyOtp === '' || user.verifyOtp !== otp) {
            return res.json({ Success: false, message: 'Invalid OTP' });
        }

        if (user.verifyOtpExpireAt < Date.now()) {
            return res.json({ Success: false, message: 'OTP Expired' });
        };

        user.isAccountVerified = true;
        user.verifyOtp = '';
        user.verifyOtpExpireAt = 0;

        await user.save();
        return res.json({ Success: true, message: 'Email Verified Successfully' });


    } catch (error) {
        return res.json({ Success: false, message: error.message })
    }
}

// checking if the user is authenticated
export const isAuthenticated = async (req, res) => {

    try {
        return res.json({ Success: true })
    } catch (error) {
        return res.json({ Success: false, message: error.message })
    }
}

// now we can make password change request (reset password)

export const sendResetOtp = async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.json({ Success: false, message: 'Please enter you Email address' });
    }

    try {

        const user = await userModel.findOne({ email });
        if (!user) {
            return res.json({ Success: false, message: 'User not found' });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000;

        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            text: `Your Password Reset OTP is: ${otp}`,
        };

        await transporter.sendMail(mailOptions);
        res.json({ Success: true, message: 'Password Reset Otp Sent on Email' })

    } catch (error) {
        return res.json({ Success: false, message: error.message });
    }
}

//reset user password

export const resetPassword = async (req, res) => {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
        return res.json({ Success: false, message: 'Missing Details, Email, OTP & new password is required' });
    }

    try {

        const user = await userModel.findOne({ email });
        if (!user) {
            return res.json({ Success: false, message: "User not found" });
        }

        if (user.resetOtp === '' || user.resetOtp !== otp) {
            return res.json({ Success: false, message: "Invalid OTP" });
        }

        if (user.resetOtpExpireAt < Date.now()) {
            return res.json({ Success: false, message: 'OTP is Expired' })
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.resetOtp = '';
        user.resetOtpExpireAt = 0;
        await user.save();
        return res.json({ Success: true, message: 'Password has been Reset Successfully' });

    } catch (error) {
        return res.json({ Success: false, message: error.message });
    }
} 