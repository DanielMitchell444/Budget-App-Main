import React from "react";
import styles from '../Styles/App.module.css'
const ForgotPassword = () => {
    return(
     <div className= {styles.wrappedContainer}>
     <div className= {styles.forgotPasswordContainer}>
    <h1>Reset Password</h1>
    <div className= {styles.inputFields2}>
    <label for = "Email">Email</label>
     <input type = "email"
     placeholder="Email"
     />
    </div>
    <div className= {styles.inputFields}>
         <input 
         type = "submit" 
         value= "Reset" 
         className= {styles.reset}
         />
     </div>
     </div>
     </div>
    )
}

export default ForgotPassword