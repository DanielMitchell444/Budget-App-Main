
import axios from 'axios';
import styles from '../src/Styles/App.module.css'
import Login from './Components/Login';
import Menu from './Components/Menu';
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
    Password: ""
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
    available_account_balance: "",
    current_account_balance: "",
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

      const { message, first_login } = response.data; // Extract tokens from the response
      console.log(message)
      if(first_login === true){
      // Store tokens securely
       alert('Welcome, please complete your profile')
       window.location.href = "/Setup"
      } else{
        alert(message)
        console.log(first_login)
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
 const handleProfile = async (e) => {
   e.preventDefault();
   if(steps === 1){
   try{
    await axios.post("http://localhost:8000/api/validate_basic_info/", {
      first_name: profile.first_name,
      last_name: profile.last_name,
      gender: profile.gender,
      address: profile.address
   })
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
    try {
      const response = await axios.get("http://localhost:8000/api/create_link_token/");
      console.log("Step 3 Data:", response.data);
    } catch (error) {
      if (error.response) {
        console.log("Step 3 Server Error:", error.response.data.message);
      } else if (error.request) {
        console.log("Step 3 Request Error:", error.request);
      } else {
        console.log("Step 3 General Error:", error.message);
      }
    }
  }

    // Step 1: Fetch the link token from your backend server


  }

  

  const fetchLinkToken = async () => {
    try {
      const token = localStorage.getItem('auth_token'); // Fetch your auth token if required
      const response = await axios.post(
        'http://localhost:8000/api/create_link_token/', {}, {
        
        headers: {
          'Authorization': `Bearer ${token}`,  // Ensure "Bearer" followed by a space and the token
        }
        });
      setLinkToken(response.data.link_token);
      setLoading(false); // Set loading to false after fetching token
    } catch (error) {
      console.error('Error fetching link token:', error.response?.data || error.message);
      setLoading(false); // Stop loading even if there’s an error
      console.log(linkToken)
    }
  };

  const exchangePublicToken = async (publicToken) => {
    try {
      const response = await axios.post('http://localhost:8000/api/exchange_public_token/', { public_token: publicToken });
      console.log('Access token:', response.data.access_token);
      setLinkToken(response.data.linkToken)
    } catch (error) {
      console.error('Error exchanging public token:', error);
    }
  };

  useEffect(() => {
    fetchLinkToken();
  }, []);

  const { open, ready } = usePlaidLink({
    token: linkToken,
    onSuccess: (public_token, metadata) => {
      console.log('Public token:', public_token);
      // Send public_token to your backend
    },
    onExit: (err, metadata) => {
      if (err) {
        console.error('Error during Plaid Link:', err);
      }
    },
  });
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
      onSuccess={exchangePublicToken}
      open = {open}
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
