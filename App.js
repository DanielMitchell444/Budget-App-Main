
import axios from 'axios';
import styles from '../src/Styles/App.module.css'
import Login from './Components/Login';
import Menu from './Components/Menu';
import { useTellerConnect } from 'teller-connect-react';
import { useEffect, useState } from 'react';
import { BrowserRouter,  Routes, Route } from 'react-router-dom';
import SignUp from './Components/SignUp';
import LandingPage from './Components/LandingPage';
import Nav from './Components/Nav';
import About from './Components/About';
import News from './Components/News';
import Contact from './Components/Contact';
import ForgotPassword from './Components/ForgotPassword';
import { signInWithPopup } from 'firebase/auth';
import { auth, googleProvider } from './Components/firebase';
import Info from './Components/Info';
import Dashboard from './Components/Dashboard';
import Setup from './Components/Setup';
import { usePlaidLink } from 'react-plaid-link';
import { useTellerLink } from 'teller-connect-react'; // Import Teller Link hook
function App() {
  //Handing input fields //
   
  const [username, setUserName] = useState("");
  const [password, setPassWord] = useState("")
  const [firstName, setFirstName] = useState("")
  const [loading, setLoading] = useState(false)
  const [lastName, setLastName] = useState("")
  const [birthday, setBirthDay] = useState("")
  const [email, setEmail] = useState("")
  const [complete, isComplete] = useState(false) 
  const [gender, setGender] = useState("")
  const [isValidEmail, setIsValidEmail] = useState()
  const [menu, setShowMenu] = useState(false)
  const [steps, nextSteps] = useState(1)

  const [data, setFormData] = useState({
    FirstName: "",
    LastName: "",
    Username: "",
    Password: "",
    Email: "",
    Birthday: "",
  })



  const [loginData, setLoginData] = useState({
    Email: "",
    Password: "",
    access_token: "",
    refresh_token: ""
  })

  const [loginData2, setLoginData2] = useState({
    Email: "",
    Password: ""
  })

  const [profile, setProfile] = useState({
    first_name : "",
    last_name : "",
    gender: "",
    address: "",
    city: "",
    state: "",
    account_number: "",
    bank_name: "",
    routing_number: "",
    amount: "",
    transaction_date: "",
    transaction_description: "",
    currency: ""

  })

  const [valid, setIsValid] = useState()

  const [error, setError] = useState("")
  const [generalError, setGeneralError] = useState("")
  const [linkToken, setLinkToken] = useState('');

  const handleSignIn = async () => {
    try {
      const result = await signInWithPopup(auth, googleProvider);
      const token = await result.user.getIdToken();
      const response = await fetch("http://localhost:8000/auth/google/", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ token }),
      });
      const data = await response.json();
      console.log("Backend Response:", data);
      
      if (data.is_first_time_login) {
        // Handle first-time login, e.g., redirect to a setup page or show a welcome message
        window.location.href = "/Setup";
      } else {
        window.location.href = "/Dashboard";  // Normal redirect to the dashboard
      }
  
    } catch (error) {
      console.error("Error signing in with Google:", error);
    }
  };
 
  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...data, [name]: value });
};

const handleLoginChange = (e) => {
  const { name, value } = e.target;
  setLoginData((prev) => ({ ...prev, [name]: value }));
};


const handleProfileChange = (e) => {
  const {name, value} = e.target;
  setProfile((prev) => ({...prev, [name]: value}))
}


  const openTellerLink = () => {
    if (linkToken) {
      const teller = new window.TellerLink({
        token: linkToken,
        onSuccess: (publicToken) => {
          // You will receive the public token here after the user successfully links their bank account
          console.log("Linking successful:", publicToken);
          
          // You can send the publicToken to your backend to exchange for access and refresh tokens
          fetch("/api/exchange_public_token/", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ public_token: publicToken }),
          });
        },
        onExit: (error) => {
          if (error) {
            console.error("Linking exited with error:", error);
          } else {
            console.log("Linking exited.");
          }
        },
      });

      teller.open();
    }
  };
const handleLogin = async (e) => {
  e.preventDefault();

  if (steps === 1) {
    // Step 1: Validate email
    try {
      const response = await axios.post("http://localhost:8000/api/login_email/", {
        Email: loginData.Email,
      });

      console.log("Email validated:", response.data);
      setError(""); // Clear any previous errors
      nextSteps(steps + 1); // Move to the next step
    } catch (error) {
      if (error.response) {
        console.error(error.response.data.message);
        setError(error.response.data.message || "Error validating email");
      } else {
        console.error("Unexpected error:", error.message);
        setError("Something went wrong. Please try again.");
      }
    }
  } else if (steps === 2) {
    // Step 2: Authenticate user
    try {
      const response = await axios.post("http://localhost:8000/api/login_user/", {
        Email: loginData.Email,
        Password: loginData.Password,
      });

      console.log("Login successful:", response.data);
      alert("Login Successful! Redirecting...");
      setError(""); // Clear any errors
      localStorage.setItem("token", response.data.token); // Save the token
      window.location.href = "/Dashboard"
      nextSteps(0)
    } catch (error) {
      if (error.response) {
        console.error("Login failed:", error.response.data.message);
        setError(error.response.data.message || "Error logging in");
      } else {
        console.error("Unexpected error:", error.message);
        setError("Something went wrong. Please try again.");
      }
    }
  }
};

const showMenu = () => {
  setShowMenu(!menu)
}

const handleSubmitLogIn = async (e) => {
  e.preventDefault();

  if (steps === 1) {
    // Step 1: Validate email
    try {
      await axios.post(
        "http://localhost:8000/api/validate_login_email/",
        { email: loginData.Email },
        {
          headers: {
            "Content-Type": "application/json", // Ensure JSON content type
          },
        }
      );

      nextSteps(steps + 1); // Proceed to the next step
      console.log("Email is valid");
    } catch (error) {
      if (error.response) {
        setError(error.response.data.message); // Display error message
        console.log("Error validating email:", error.response.data.message);
      }
    }
  } else if (steps === 2) {
    // Step 2: Validate credentials and retrieve token
    try {
      const response = await axios.post(
        "http://localhost:8000/api/validate_login_details/",
        {
          email: loginData.Email,
          password: loginData.Password,
        },
        {
          headers: {
            "Content-Type": "application/json", // Ensure JSON content type
          },
        }
      );

      const {first_login, access_token, refresh_token } = response.data; // Extract tokens from the response
      localStorage.setItem('access_token', access_token)
      localStorage.setItem('refresh_token', refresh_token)
      if(first_login === true){
      // Store tokens securely
      alert("Welcome! Please complete your profile")
      window.location.href = "/Setup"
       localStorage.setItem('access_token',access_token)
       localStorage.setItem('refresh_token', refresh_token)
       console.log('Access Token', access_token)
       console.log('Refresh Token', refresh_token)
      
      } else{
        console.log(first_login)
        localStorage.setItem('access_token',access_token)
        localStorage.setItem('refresh_token', refresh_token)
        console.log('Access Token', access_token)
        console.log('Refresh Token', refresh_token)
       }

    } catch (error) {
      if (error.response) {
        setError(error.response.data.message); // Display error message
        console.log("Error during login:", error.response.data.message);
      }
    }
  }
};




   const nextStep = async (e) => {
    e.preventDefault()
    if (steps === 1) {
      // Send email to the backend (Step 1)
      try {
        await axios.post("http://localhost:8000/api/register_email/",{
       email: loginData.Email
        }
      );
        nextSteps(steps + 1);
        console.log(loginData)
        console.log('this works')
      } catch (error) {
        if(error.response){
          setError(error.response.data.message);
          console.log(error.response.data)
        console.error(error.response.data.message);
        console.log(data)

        }
      }
    } else if (steps === 2) {
      // Send personal info to the backend (Step 2)
      e.preventDefault()
      try {
        await axios.post("http://localhost:8000/api/register_details/", {
          email: loginData.Email,
          password: loginData.Password
        });
        alert("Succesfull Sign In, Returning to login page")
        window.location.href = "/Login"
        console.log('this works btw')

      } catch (error) {
        console.error(error.response.data || {});
        console.log(error.response.data.message)
        setError(error.response.data)
      }
      }
    }

  const handeBack = () => {
    if(steps > 1){
      nextStep(steps - 1)
    }
  }
  

const handleSubmit = async (e) => {
      e.preventDefault();

      setError({})
      setGeneralError("")

      const newErrors = {}

  if (!loginData.Email) newErrors.Email = "Email is required.";

      if(Object.keys(newErrors).length > 0){
        setError(newErrors)
        return
      }
      try{
      const response = await axios.post("http://localhost:8000/api/Login/",{
        Email: loginData.Email,
        Password: loginData.Password
      }, {
        headers: {
          'Content-Type': 'application/json',
        }})
      localStorage.setItem('auth_token', response.data.token)
      console.log(response.data.token);
       window.location.href = "/"
       alert("Succesfully signed up")
       console.log(data)
       
        
      } catch(error){
        if(error.response){
          console.log('Backend Error', error.response.data)
          console.log(error.response.data.message)
          setError(error.response.data || {})
          setGeneralError(error.response.data.message || '')
          console.log(data)
        }
        else{
          setGeneralError("An unexpected error has occured")
        }
      }
      }

      const { open, ready } = useTellerConnect({
        applicationId: "app_p76c29q36r8ae6hq9a000", // Teller application ID
        environment: "sandbox",
        onSuccess: async (auth) => {
            console.log("Teller authentication successful:", auth);
    
            const tellerAccessToken = auth.accessToken; // Extract the Teller access token
            const access = localStorage.getItem('access_token')
            console.log("Teller Access Token:", tellerAccessToken);
    
            // Send the Teller access token to the backend
            try {
                const response = await axios.post("http://localhost:8000/api/teller/accounts/", {
                    tellerAccessToken: tellerAccessToken,
                
                },
                {
      
                  headers: {
                      'Content-Type': 'application/json',
                  },
            });
                
    
                if (response.data) {
                    console.log("Bank information:", response.data);
                    // Handle the bank information (e.g., display it, store it, etc.)
                } else {
                    console.error("Failed to fetch bank information.");
                }
            } catch (error) {
                console.error("Error:", error.message);
            }
        },
        onExit: () => {
            console.log("Teller API window closed by user.");
        },
    });
 const handleProfile = async (e) => {
   e.preventDefault();

   if(steps === 1){
   try{
    await axios.post("http://localhost:8000/api/validate_basic_info/", {
      first_name: profile.first_name,
      last_name: profile.last_name,
      email: loginData.Email,
      gender: profile.gender,
      birthday: profile.birthday
   },
   {
    headers: {
      "Content-Type": "application/json",
    },
  }
  )
   nextSteps(steps + 1)
    } catch(response){
      if(error.response){
      setError(error.response.data || {})
      console.log(error.response.data)
      console.log(error.response.data.message)
  }
}
} else if(steps === 2){
     try{
     await axios.post("http://localhost:8000/api/validate_address_info/", {
     address: profile.address,
     city: profile.city,
     state: profile.state
     })
     nextSteps(steps + 1)
     } catch(response){
     if(error.response){
      setError(error.response.data)
      console.log(error.response.data.message)
     }      
    }

  } else if (steps === 3) {
      if(ready){
        open()
      }
      
 }

  // Now use `useTellerConnect` inside the component
 
}

const sendToBackend = async (auth) => {
  const token3 = localStorage.getItem("access_token"); // Ensure the user is authenticated
  try {

     
  
    await axios.post(
      "http://localhost:8000/api/save_complete_profile/",
      {
        first_name: profile.first_name,
        last_name: profile.first_name,
        Email: loginData.Email,
        bank_name: auth.bank_name,
        account_number: auth.account_number,
        routing_number: auth.routing_number,
        available: auth.available,
        amount: auth.amount,
        transaction_date: auth.transaction_date,
        transaction_description: auth.transaction_description,
        currency: auth.currency,
      },
      {
      headers: {
        Authorization: `Bearer ${token3}`, // Include the token for authenticated requests
      },
    }
    )
    console.log('Saved Succesfully')
    console.log(token3)
  } catch (error) {
    if (error.response?.status === 401) {
      console.error("Authentication error. Token might be expired.");
      // Handle token refresh or redirect to login
      const token4 = localStorage.getItem('access_token')
      console.log(token4)
      console.log(token3)
    } else {
      console.error("Error saving bank information:", error.response?.data || error.message);
    }
  }
}



  const exchangePublicToken = async (publicToken) => {
    try {
      const response = await axios.post('http://localhost:8000/api/exchange_public_token/', { public_token: publicToken });
      console.log('Access token:', response.data.access_token);
      setLinkToken(response.data.linkToken)
    } catch (error) {
      console.error('Error exchanging public token:', error);
    }
  };



  return (
    <div className= {styles.App}>
      <div className= {styles.landingContainer2}>
    <main className= {styles.mainContent}>
    <Routes>
      <Route path = "/" element= {
        <>
           <Nav 
           menu = {menu}
           toggleMenu={showMenu}
           
           />
          <LandingPage
          show = {menu}

          />
          </>
      }

      />

      <Route path = "/Dashboard" element = 

      {
      <Dashboard />
      }

      />
      <Route path = "/About" element = {
      <>
        <Nav 
           menu = {menu}
           toggleMenu={showMenu}
           
           />
       <About />

       </>
      }

      />
      <Route path = "/News" element = {
        <News />
      
      }

      />

      <Route path = "/Contact" element = {
       <Contact />
      }

      />
      <Route path = "/Login" element= { <Login 
loginData = {loginData}
username = {username}
data = {loginData}
password = {password}
handleSubmit = {handleSubmitLogIn}
onChange={handleLoginChange}
valid = {valid}
ready = {ready}
error = {error}
steps = {steps}
google = {handleSignIn}
      
      />} />
    

      <Route path = "/SignUp" element={<SignUp 
       valid = {valid}
       data = {loginData}
       onChange={handleLoginChange}
       onSubmit = {handleSubmit}
       google = {handleSignIn}
       nextStep = {nextStep}
       steps = {steps}
       handleBack = {handeBack}
       error = {error}
       generalError = {generalError}
      />} />

      <Route path = "/ForgotPassword" element = {

        <ForgotPassword />
      }
      />

      <Route path = "/Info" element = {
      <Info />
      }

      />
      <Route path = "/Setup" element = {
      <Setup 
      data = {profile}
      onChange = {handleProfileChange}
      onSubmit = {handleProfile}
      steps = {steps}
      error = {error}
      linkToken = {linkToken}
      openTellerLink = {openTellerLink}
      onSuccess={exchangePublicToken}
      open = {open}
      ready = {ready}
      generalError = {generalError}
      linkToken2 = {linkToken}
      />
      }
      />
      </Routes>
      </main>
      </div>
    </div>

  );
}
export default App;
