import React from "react";
import styles from '../Styles/App.module.css'
import { Link } from "react-router-dom";
const Info = ({onSubmit}) => {
    return(
    <div className= {styles.wrappedContainer}>
    <div className= {styles.containerSignUp}>
    <div className= {styles.content}>
     <h1>Create your account</h1>
    </div>
    <form className= {styles.form} onSubmit={onSubmit}>
     <div className= {styles.inputFields2}>
      <input type = "text"
      placeholder="Email"

      />
     </div>
     <div className= {styles.inputFields2}>
      <input type = "text"
      placeholder="Password"

      />
     </div>
     <div className={styles.inputFields}>
        <input type="submit" value="Continue" />
      </div>
    <div className= {styles.back}>
     <Link to = "/SignUp"
     className= {styles.linkSign}
     >
     Go Back
     </Link>
    </div>

    </form>
    </div>
     
    </div>
    )
}

export default Info;