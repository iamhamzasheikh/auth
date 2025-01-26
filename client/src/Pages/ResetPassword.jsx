import { useState, useRef, useContext } from "react";

import { assets } from "../assets/assets"
import { useNavigate } from "react-router-dom"
import { AppContext } from "../Context/AppContext";
import axios from "axios";
import { toast } from "react-toastify";


const ResetPassword = () => {
    const inputRefs = useRef([]);
    const navigate = useNavigate();
    const [email, setEmail] = useState('')
    const [newPassword, setNewPassword] = useState('');
    const [isEmailSent, setIsEmailSent] = useState('');
    const [otp, setOtp] = useState(0);
    const [isOptSubmited, setIsOptSubmited] = useState(false);

    const { backendUrl } = useContext(AppContext);
    axios.defaults.withCredentials = true;


    // enter otp using keyboard
    const handleInput = (e, index) => {
        if (e.target.value.length > 0 && index < inputRefs.current.length - 1) {
            inputRefs.current[index + 1].focus();
        }
    }

    // deleting otp using backspace

    const handleKeyDown = (e, index) => {
        if (e.key === 'Backspace' && e.target.value === '' && index > 0) {
            inputRefs.current[index - 1].focus();
        }
    }

    //function for paste otp 

    const handlePaste = (e) => {
        const paste = e.clipboardData.getData('text');
        const pasteArray = paste.split('');

        pasteArray.forEach((char, index) => {
            if (inputRefs.current[index]) {
                inputRefs.current[index].value = char;
            }
        })
    }


    const onSubmitEmail = async (e) => {
        e.preventDefault();
        try {
            const { data } = await axios.post(`${backendUrl}/api/auth/send-reset-otp`, { email });
            data.Success ? toast.success(data.message) : toast.error(data.message);
            data.Success && setIsEmailSent(true);

        } catch (error) {
            toast.error('Error sending email:', error);
            console.log(error)
        }
    }

    // when we submit otp

    const onSubmitOTP = async (e) => {
        e.preventDefault();

        const otpArray = inputRefs.current.map(e => e.value);
        setOtp(otpArray.join(''));
        setIsOptSubmited(true);
    }


    const onSubmitNewPassword = async (e) => {
        e.preventDefault();

        try {
            const { data } = await axios.post(`${backendUrl}/api/auth/reset-password`, { email, otp, newPassword });

            data.Success ? toast.success(data.message) : toast.error(data.message);
            data.Success && navigate('/login');

        } catch (error) {
            toast.error(error.message);
        }
    }


    return (
        <div className="flex items-center justify-center min-h-screen bg-gradient-to-br from-blue-200 to-purple-400">
            <img onClick={() => navigate('/')} src={assets.logo} className="absolute left-5 sm:left-20 top-5 w-28 sm:w-32 cursor-pointer" />

            {/* enter email id */}

            {!isEmailSent && (
                <form onSubmit={onSubmitEmail} className="bg-slate-900 p-8 rounded-lg shadow-lg w-auto text-sm" >
                    <h1 className="text-white text-2xl font-semibold text-center mb-4">Reset Password</h1>
                    <p className="text-center mb-6 text-indigo-300">Enter you register Email here.</p>

                    <div className="flex items-center gap-3 mb-4 w-72 px-5 py-2.5 rounded-full bg-[#333A5C]">
                        <img className="w-5 h-5" src={assets.mail_icon} />
                        <input className="bg-transparent outline-none text-white flex-grow autofill-fix"
                            type="email"
                            placeholder="Enter Email ID"
                            value={email}
                            onChange={e => setEmail(e.target.value)}
                            required />
                    </div>
                    <button className="w-full py-2.5 bg-gradient-to-r from-indigo-500 to-indigo-900 rounded-full">Submit</button>
                </form>
            )}

            {/* OTP input form */}

            {!isOptSubmited && isEmailSent && (
                <form onSubmit={onSubmitOTP} className="bg-slate-900 p-8 rounded-lg shadow-lg w-auto text-sm">

                    <h1 className="text-white text-2xl font-semibold text-center mb-4">Reset Password OTP</h1>
                    <p className="text-center mb-6 text-indigo-300">Enter 6 Digit code sent to your Email id.</p>

                    <div className="flex justify-between mb-8 " onPaste={handlePaste}>

                        {Array(6).fill(0).map((_, index) => (
                            <input className="w-12 h-12 bg-[#333A5C] text-white text-center text-xl rounded-md"
                                type="text"
                                maxLength='1'
                                key={index}
                                ref={e => inputRefs.current[index] = e}
                                onInput={(e) => handleInput(e, index)}
                                onKeyDown={(e) => handleKeyDown(e, index)}
                                required />
                        ))}
                    </div>
                    <button className="w-full py-2.5 bg-gradient-to-r from-indigo-500 to-indigo-900 rounded-full">Submit</button>

                </form>
            )}

            {/* Enter new password */}

            {isOptSubmited && isEmailSent && (
                <form onSubmit={onSubmitNewPassword} className="bg-slate-900 p-8 rounded-lg shadow-lg w-auto text-sm" >
                    <h1 className="text-white text-2xl font-semibold text-center mb-4">New Password</h1>
                    <p className="text-center mb-6 text-indigo-300">Enter new password here.</p>

                    <div className="flex items-center gap-3 mb-4 w-72 px-5 py-2.5 rounded-full bg-[#333A5C]">
                        <img className="w-5 h-5" src={assets.lock_icon} />
                        <input className="bg-transparent outline-none text-white flex-grow autofill-fix"
                            type="password"
                            placeholder="Enter New Password"
                            value={newPassword}
                            onChange={e => setNewPassword(e.target.value)}
                            required />
                    </div>
                    <button className="w-full py-2.5 bg-gradient-to-r from-indigo-500 to-indigo-900 rounded-full">Submit</button>
                </form>
            )}




        </div>
    )
}

export default ResetPassword
