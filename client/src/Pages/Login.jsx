import { useContext, useState } from "react"
import { assets } from "../assets/assets";
import { useNavigate } from "react-router-dom";
import { AppContext } from "../Context/AppContext";
import axios from 'axios'
import { toast } from "react-toastify";

const Login = () => {

  const navigate = useNavigate();

  const { backendUrl, setIsLoggedin, getUserData } = useContext(AppContext)

  const [state, setState] = useState('Login');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const onSubmithandler = async (e) => {
    try {
      e.preventDefault();
      axios.defaults.withCredentials = true;

      if (state === 'Sign Up') {
        console.log("Sending signup request:", { name, email, password });
        const response = await axios.post(backendUrl + '/api/auth/register', { name, email, password });
        console.log("Signup Response:", response);

        if (response.status === 200) {
          toast.success("Signup successful!");
          setIsLoggedin(true);
          getUserData()
          setTimeout(() => {
            navigate('/');
          }, 1000);
        } else {
          console.error("Signup failed:", response.data?.message);
          toast.error(response.data?.message || "Signup failed");
        }
      } else {
        console.log("Sending login request:", { email, password });
        const response = await axios.post(backendUrl + '/api/auth/login', { email, password });
        console.log("Full login response:", response);

        if (response.status === 200) {
          console.log("Login successful");
          toast.success("Login successful!");
          setIsLoggedin(true);
          getUserData()
          setTimeout(() => {
            navigate('/');
          }, 1000);
        } else {
          console.error("Login failed:", response.data?.message);
          toast.error(response.data?.message || "Login failed");
        }
      }
    } catch (error) {
      // Detailed error logging
      console.error("Authentication error details:", {
        error: error,
        response: error.response,
        data: error.response?.data,
        message: error.message
      });

      // Handle error message display
      const errorMessage = error.response?.data?.message ||
        error.response?.data ||
        error.message ||
        "Authentication failed";

      toast.error(errorMessage);
    }
  };


  return (
    <div className="flex items-center justify-center min-h-screen px-6 sm:px-0 bg-gradient-to-br from-blue-200 to-purple-400">
      <img onClick={() => navigate('/')} src={assets.logo} className="absolute left-5 sm:left-20 top-5 w-28 sm:w-32 cursor-pointer" />

      <div className="bg-slate-900 p-10 rounded-lg shadow-lg w-full sm:w-96 text-indigo-300 text-sm">
        <h2 className="text-3xl font-semibold text-white text-center mb-3"> {state === 'Sign Up' ? 'Create Account' : 'Login'} </h2>
        <p className="text-center text-sm mb-6">{state === 'Sign Up' ? 'Create your Account' : 'Login your Account'}</p>
        <form onSubmit={onSubmithandler}>

          {state === "Sign Up" && (
            <div className="mb-4 flex items-center gap-3 w-full px-5 py-2.5 rounded-full bg-[#333A5C]">
              <img src={assets.person_icon} alt="" />
              <input onChange={e => setName(e.target.value)} value={name} className="bg-transparent outline-none text-white" type="text" name="name" placeholder="Full Name" id="" required />
            </div>
          )}
          <div className="mb-4 flex items-center gap-3 w-full px-5 py-2.5 rounded-full bg-[#333A5C]">
            <img src={assets.mail_icon} alt="" />
            <input onChange={e => setEmail(e.target.value)} value={email} className="bg-transparent outline-none text-white" type="email" name="email" placeholder="Enter Email" id="" required />
          </div>

          <div className="mb-4 flex items-center gap-3 w-full px-5 py-2.5 rounded-full bg-[#333A5C]">
            <img src={assets.lock_icon} alt="" />
            <input onChange={e => setPassword(e.target.value)} value={password} className="bg-transparent outline-none text-white" type="password" name="password" placeholder="Password" id="" required />
          </div>

          <p onClick={() => navigate('/reset-password')} className="mb-4 text-indigo-500 cursor-pointer">Forgot Password?</p>

          <button className="w-full py-2.5 rounded-full bg-gradient-to-r from-indigo-500 to-indigo-900 text-white font-medium ">
            {state === 'Sign Up' ? "SignUp" : "Login"}</button>
        </form>


        {
          state === "Sign Up" ? (
            <p className="text-gray-400 text-center text-xs mt-4">Already have an Account? {''}
              <span className="text-blue-400 cursor-pointer underline" onClick={() => setState('Login')}> Login here</span></p>
          ) : (
            <p className="text-gray-400 text-center text-xs mt-4">Do not have an Account? {''}
              <span className="text-blue-400 cursor-pointer underline" onClick={() => setState('Sign Up')}> Signup</span></p>
          )
        }




      </div>
    </div>
  )
}

export default Login
