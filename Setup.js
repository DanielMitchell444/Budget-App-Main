import React from "react";
import styles from '../Styles/App.module.css'
import { PlaidLink } from 'react-plaid-link';

const Setup = ({data, onChange, steps, error, ready, openTellerLink, generalError, exchangePublicToken, onSubmit,onSuccess, open, linkToken2}) => {
    return(
    <div className= {styles.wrappedContainer}>
    <div className= {styles.containerSignUp}>
    <div className= {styles.content}>
        <h1>Complete Profile</h1>
        <p>Lets get more information about you!</p>
    </div>
    <div className = {styles.progressBar}>
  <div className= {styles.step}>1</div>
  <div className= {styles.line}></div>
  <div className= {styles.step}>2</div>
  <div className= {styles.line}></div>
  <div class= {styles.step}>3</div>
  <div className= {styles.line}></div>
  <div class= {styles.step}>4</div>
  
  
</div>
    <form className= {styles.form}
    onSubmit={onSubmit}
    >
    {steps === 1 && (
      <>
     <div className= {styles.inputFields2}>
     <input type = "text"
     placeholder="Full Name"
     name = "first_name"
     value = {data.first_name}
     onChange={onChange}

     />
     <input type = "text"
     placeholder="Birthday"
     name = "birthday"
     value = {data.birthday}
     onChange={onChange}
     />
     <input type = "text"
     placeholder="Gender"
     name = "gender"
     value = {data.gender}
     onChange={onChange}

     />
        <div className= {styles.inputFields}>
      <input type = "submit" value= "Continue" 
      className= {styles.login}
      />
    </div>
    {console.log(error)}

     </div>
     </>
    )}
    {steps === 2 && (
     <>
        <div className= {styles.inputFields2}>
     <input type = "text"
     placeholder="Address"
     name = "address"
     value = {data.address}
     onChange={onChange}

     />
     <input type = "text"
     placeholder="City"
     name = "city"
     value = {data.city}
     onChange={onChange}
     />
     <input type = "text"
     placeholder="State"
     name = "state"
     value = {data.state}
     onChange={onChange}

     />
        <div className= {styles.inputFields}>
      <input type = "submit" value= "Continue" 
      className= {styles.login}
      />
    </div>
    {console.log(error)}

     </div>
     </> 
    )}
    {steps === 3 && (
     <>
       <h1>Link Your Bank Account</h1>
       <button onClick={() => open()} disabled = {!ready}>
        Connect a bank account
       </button>

        <div className= {styles.inputFields}>
      <input type = "submit" value= "Continue" 
      className= {styles.login}
      />
    </div>
    {console.log(error)}

     </>
    )}
    </form>
    </div>
    </div>
    )
}

export default Setup