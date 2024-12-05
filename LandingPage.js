import React from 'react'
import styles from '../Styles/App.module.css'
import { Route, Link } from 'react-router-dom'
import Nav from './Nav'
const LandingPage = ({show, menu}) => {
    return(
    <div className= {styles.landingPageContainer}>
     <div className= {styles.landingContainer}>
      <h1 className= {styles.heading}>Explore the possibilities of Budgeting with Echo Software</h1>
      <p>Unleash the power of healthy budgeting within Echo Budgeting. Upgrade your budgeting potential with Echo, your journey to better budgeting starts with Echo.</p>
     <Link to = "/Signup">
     <button className= {styles.getStarted}>Get Started</button>
     </Link>
     </div>
     </div>
    )
}

export default LandingPage