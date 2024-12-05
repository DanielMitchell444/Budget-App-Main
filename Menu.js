import React from "react";
import Login from '../Components/Login';
import styles from '../Styles/App.module.css'
const Menu = ({handleChange, input}) => {
 return(
<div className= {styles.container2}>
 <Login 
 input = {input}
 handleChange = {handleChange}
 />
 </div>
 )
}

export default Menu;