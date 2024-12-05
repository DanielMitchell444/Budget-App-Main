import React from 'react';
import styles from '../Styles/App.module.css';
import { Link } from 'react-router-dom';

import { useState } from 'react';

const SignUp = ({ data, onChange, onSubmit, error, generalError, google, nextStep, steps, handleBack }) => {

 
  return (
    <div className= {styles.wrappedContainer}>
    <div className= {styles.containerSignUp}>
    <div className= {styles.content}>
     <h1>Create an account</h1>
     </div>
     <form className= {styles.form}
     onSubmit={nextStep}
     >
      {steps === 1 && (
        <>
     <div className= {styles.inputFields2}>
      <input type = "email"
      placeholder='Email'
      name = "Email"
      className={error ? styles.inputError : ''}
      value = {data.Email}
      onChange={onChange}

      />
         {error && <p className={styles.error}>{error}</p>}
     </div>
     <div className= {styles.inputFields}>
      <input type = "submit" value= "Continue" 
      className= {styles.login}
      />
    </div>
      <div className= {styles.account}>
        <p>Already have an account? 
        <Link to = "/Login"
        className= {styles.linkSign}
        >  
        Log In
        </Link>
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
      {steps === 2 && (
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
      {steps === 3 && (
      <>
      <div className = {styles.verify}>
        <div className= {styles.verifyText}>
          <h2>Verify Your Email</h2>
          <p>We sent an email to {data.Email},
           This page will go back to the homepage when your email
           is verified
          </p>
        </div>
      </div>
      </>
      )}
     </form>
     </div>
    </div>
  );
};

export default SignUp;
