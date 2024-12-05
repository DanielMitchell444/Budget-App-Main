import React from "react";
import { Link } from "react-router-dom";
import styles from '../Styles/App.module.css'
import { faBars } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
const Nav = ({menu, toggleMenu}) => {
    return(
        <header className= {styles.header}>
        <nav className= {styles.nav}>
          <Link to = "/" className= {styles.navLogo}>
           <h1>Echo Software</h1>
          </Link>
          <div className= {styles.navMenu}>

      <ul className={`${styles.navLinks} ${menu ? styles.active : ""}`}>
          <li>
          <Link to = "/"  className= {styles.navLinks2}>Home</Link>
          </li>
          <li>
          <Link to = "/Setup"  className= {styles.navLinks2}>About Us</Link>
          </li>
          <li>
          <Link to = "/News"  className= {styles.navLinks2}>News</Link>
          </li>
          <li>
          <Link to = "/Contact"  className= {styles.navLinks2}>Contact Us</Link>
          </li>
          <li>
          <Link to = "/SignUp"  className= {styles.navLink_cta}>Sign Up</Link>
          </li>
          <li>
          <Link to = "/Login" className= {styles.navLink_cta}>Login</Link>
          </li>
          </ul>
          </div>
          
          
          <div className= {styles.toggleMenu}>
            <FontAwesomeIcon 
            icon={faBars} 
            className= {styles.toggle}
            onClick={toggleMenu}
            />
          </div>
        </nav>
      </header>
    )
}

export default Nav