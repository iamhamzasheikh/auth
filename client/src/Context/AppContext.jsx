import axios from "axios";
import { createContext, useEffect, useState } from "react";
import { toast } from "react-toastify";


export const AppContext = createContext();

export const AppContextProvider = (props) => {

    axios.defaults.withCredentials = true;
    // const backendUrl = import.meta.env.VITE_BACKEND_URL;
    const backendUrl = "http://localhost:4000";
    const [isLoggedin, setIsLoggedin] = useState(false);
    const [userData, setUserData] = useState(false);


    // this function is for checking user is valid or not 

    const getAuthState = async () => {
        try {
            const { data } = await axios.get(backendUrl + '/api/auth/is-auth');
            console.log('Auth State Response:', data); // Debug Response
            if (data.Success) {
                setIsLoggedin(true);
                getUserData();
            }
        } catch (error) {
            console.error('Error in getAuthState:', error);
            toast.error(error.message);
        }
    }


    // this function is for getting user Data 
        const getUserData = async () => {
            try {
                const {data} = await axios.get(backendUrl + '/api/user/data');
                data.success ? setUserData(data.userData) : toast.error(data.message);
                console.log('User data set:', data.userData);
            } catch (error) {
                toast.error(error.message);
                console.error('Error in getUserData:', error);
            }
        }

    useEffect(() => {
        getAuthState();
    }, []);

    const value = {
        backendUrl,
        isLoggedin,
        setIsLoggedin,
        userData,
        setUserData,
        getUserData,

    }
    return (
        <AppContext.Provider value={value}>
            {props.children}
        </AppContext.Provider>
    );
}

