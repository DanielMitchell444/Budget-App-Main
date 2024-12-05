import React from "react";
import styles from '../Styles/App.module.css'
import { useState } from "react";
import { Link } from "react-router-dom";
const Login = ({onChange, username, password, handleSubmit, 
  valid, loginData,
  google, data, steps, error
}) => {

 return(
<div className= {styles.wrappedContainer}>
<div className =  {styles.containerSignUp}>
 <div className= {styles.content}>
   <h1>Welcome Back!</h1>
   </div>
   <form 
   className= {styles.form}
   onSubmit={handleSubmit}
   >
    {steps === 1 && (
    <>
    <div className= {styles.inputFields2}>
      <input type = "email" placeholder="Enter Email"
       required 
       onChange={onChange}
       name = "Email"
       value = {data.Email}
       />
    </div>
    <div className= {styles.inputFields}>
      <input type = "submit" value= "Continue" 
      className= {styles.login}
      />
    </div>
    <div className= {styles.account}>
        <p>Don't have an account? 
          
          <Link to = "/Signup"
          href = ""
          className= {styles.linkSign}
          >Sign Up</Link>
          
          </p>
      </div>
      <div className= {styles.or}>
        <hr className= {styles.thing}></hr>
        <h2>Or</h2>
        <hr className= {styles.thing}></hr>
      </div>
      <div className= {styles.alternativeSignIn}>
        <button type = "button"
        className= {styles.googleSignInButton}
        onClick={google}
        >
       Sign in with Google
        </button>
        <button type = "button"
        className= {styles.microsoftSignInButton}
        >
         Sign in with Microsoft
        </button>
      </div>
      </>
    )}
    {steps == 2 && (
        <>
        <div className= {styles.inputFields2}>
      <input type = "email"
      placeholder='Email'
      name = "Email"
      value = {data.Email}
      onChange={onChange}

      />
      {console.log(data.Email)}
      {console.log(data.Password)}
         {error&& <p className={styles.error}>{error.Email}</p>}
     </div>
     <div className= {styles.inputFields2}>
      <input type = "password"
      placeholder='Password'
      name = "Password"
      value = {data.Password}
      onChange={onChange}

      />
         {error&& <p className={styles.error}>{error.Email}</p>}
     </div>
     <div className= {styles.inputFields}>
      <input type = "submit" value= "Continue" 
      className= {styles.login}
      />
      </div>
      <div className= {styles.account}>
        <p>
        <Link to = "/Login"
        className= {styles.linkSign}
        >  
        Go Back
        </Link>
        </p>
      </div>
      </>
    )}
   </form>
 </div>

</div>
 )
}

export default Login