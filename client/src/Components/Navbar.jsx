
import { useNavigate } from 'react-router-dom'
import { assets } from '../assets/assets'
import { useContext } from 'react'
import { AppContext } from '../Context/AppContext'
import { toast } from 'react-toastify'
import axios from 'axios'


const Navbar = () => {

    const navigate = useNavigate()
    const { userData, backendUrl, setUserData, setIsLoggedin } = useContext(AppContext);


    const sendVerificationOtp = async () => {
        try {
            axios.defaults.withCredentials = true;

            const { data } = await axios.post(backendUrl + '/api/auth/send-verify-otp');

            if (data.Success) {
                navigate('/email-verify');
                toast.success('Verification OTP sent successfully', data.message);
            } else {
                toast.error('Failed to send verification OTP', data.message);
            }
        } catch (error) {
            toast.error('Failed to send verification OTP', error.message);
        }
    }


    const logout = async () => {
        try {
            axios.defaults.withCredentials = true;
            const { data } = await axios.post(backendUrl + '/api/auth/logout');
            data.success && setIsLoggedin(false);
            data.success && setUserData(false);
            navigate('/')
        } catch (error) {
            toast.error(error.message)
        }
    }



    return (
        <div className='w-full flex justify-between items-center p-4 sm:p-6 sm:px-20 absolute top-0 '>
            <img src={assets.logo} className='w-28 sm:w-32' alt="" />

            {userData ? (
                <div className='w-10 h-10 flex justify-center items-center rounded-full bg-black text-white relative group'>
                    {userData.name[0].toUpperCase()}

                    <div className='absolute hidden group-hover:block top-0 right-0 z-10 text-black rounded pt-10'>

                        <ul className='list-none m-0 p-5 bg-gray-100 text-sm'>
                            {!userData.isAccountVerified && <li onClick={sendVerificationOtp} className='py-1 px-2 hover:bg-gray-200 cursor-pointer'>Verify email</li>}
                            <li onClick={logout} className='py-1 px-2 pr-10 hover:bg-gray-200 cursor-pointer'>Logout</li>
                        </ul>

                    </div>
                </div>
            ) :
                (
                    <button onClick={() => navigate('/login')} className='flex items-center gap-2 border border-gray-500 rounded-full px-6 py-2
                text-gray-800 hover:bg-gray-100 transition-all' >Login <img src={assets.arrow_icon} /></button>
                )}


        </div>
    )
}

export default Navbar
