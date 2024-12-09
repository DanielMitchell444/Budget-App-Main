import React from "react";
import styles from '../Styles/App.module.css'
import { Link } from "react-router-dom";
import { faBars } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faHome } from "@fortawesome/free-solid-svg-icons";
import { faChartLine } from "@fortawesome/free-solid-svg-icons";
import { faHandHoldingUsd } from "@fortawesome/free-solid-svg-icons";
import { faPiggyBank } from "@fortawesome/free-solid-svg-icons";
import { faCreditCard } from "@fortawesome/free-solid-svg-icons";
import { faUser } from "@fortawesome/free-solid-svg-icons";
import { faCog } from "@fortawesome/free-solid-svg-icons";
const DashboardMenu = () => {
    return(
        <nav className= {styles.DashboardNav}>
     <div className= {styles.dashboardGeneral}>
     <div className= {styles.logo}>
          <h1>Echo</h1>
        </div>
      <ul className= {styles.dashboardGeneralMenu}>
      <li>
        <FontAwesomeIcon
        icon = {faHome}
        className= {styles.dashboardIcons}
        />
        <Link to = "/Dashboard"
        className= {styles.dashboardNavLinks}
        >Dashboard</Link>
      </li>
      <li>
      <FontAwesomeIcon 
        icon={faChartLine} 
        className= {styles.dashboardIcons}
        />
  <Link to="/Expenses" className= {styles.dashboardNavLinks}>Expenses</Link>
  <ul className= {styles.subMenu}>
    <li>
      <Link to="/Accounts"
      className= {styles.dashboardNavLinks}
      >Accounts</Link>
    </li>
    <li>
      <Link to="/Transactions"
      className= {styles.dashboardNavLinks}
      >Transactions</Link>
    </li>
    <li>
      <Link to="/Budget"
      className= {styles.dashboardNavLinks}
      >Budget</Link>
    </li>
  </ul>
</li>
<li>
<FontAwesomeIcon 
        icon={faHandHoldingUsd} 
        className= {styles.dashboardIcons}
        />
  <Link to="/Expenses"
  className= {styles.dashboardNavLinks}
  >Debt Management</Link>
  <ul className= {styles.subMenu}>
    <li>
      <Link to="/Accounts"
      className= {styles.dashboardNavLinks}
      >Payment Tracking</Link>
    </li>
    <li>
      <Link to="/Transactions"
      className= {styles.dashboardNavLinks}
      >Repayment Strategies</Link>
    </li>
    <li>
      <Link to="/Budget"
      className= {styles.dashboardNavLinks}
      >Credit Score Managing</Link>
    </li>
  </ul>
</li>
<li>
<FontAwesomeIcon 
        icon={faPiggyBank}
        className= {styles.dashboardIcons} 
        />
  <Link to="/Expenses"
  className= {styles.dashboardNavLinks}
  >Savings</Link>
  <ul className= {styles.subMenu}>
    <li>
      <Link to="/Accounts"
      className= {styles.dashboardNavLinks}
      >Savings Goals</Link>
    </li>
    <li>
      <Link to="/Transactions"
      className= {styles.dashboardNavLinks}
      >Progress Tracker</Link>
    </li>
    <li>
      <Link to="/Budget"
      className= {styles.dashboardNavLinks}
      >Savings Suggestions</Link>
    </li>
    <li>
      <Link to="/Budget"
      className= {styles.dashboardNavLinks}
      >Savings Analysis</Link>
    </li>
  </ul>
</li>

<li>
<FontAwesomeIcon 
        icon={faCreditCard} 
        className= {styles.dashboardIcons}
        />
  <Link to="/Expenses"
  className= {styles.dashboardNavLinks}
  >Payments</Link>
  <ul className= {styles.subMenu}>
    <li>
      <Link to="/Accounts"
      className= {styles.dashboardNavLinks}
      >Track Payments</Link>
    </li>
    <li>
      <Link to="/Transactions"
      className= {styles.dashboardNavLinks}
      >Payment History</Link>
    </li>
    <li>
      <Link to="/Budget"
      className= {styles.dashboardNavLinks}
      >Settings</Link>
    </li>
  </ul>
</li>
<li>
<FontAwesomeIcon 
        icon={faUser} 
        className= {styles.dashboardIcons}
        />
      <Link to = "/profile"
      className= {styles.dashboardNavLinks}
      >Profile</Link>
      </li>
      <li>
      <FontAwesomeIcon 
        icon={faCog} 
        className= {styles.dashboardIcons}
        />
      <Link to = "/settings"
      className= {styles.dashboardNavLinks}
      >Settings</Link>
      </li>
      </ul>
      </div>
     </nav>
    )
}


export default DashboardMenu