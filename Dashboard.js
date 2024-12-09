import React from "react";
import styles from '../Styles/App.module.css'
import DashboardMenu from "./DashboardMenu";

const Dashboard = () => {
    return(
    <>
    <div className= {styles.dashboardWrappedContainer}>
    <div className= {styles.dashboardContainer}>
     <DashboardMenu />
     </div>
     <div className= {styles.mainContent2}>
      <div className= {styles.contentDashboard}>
        <div className= {styles.contentHeader}>
          <header className= {styles.contentHeader}>
            <div className= {styles.contentHeader2}>
              <h4>Good Morning Daniel</h4>
            </div>
          </header>
        </div>
        <div className= {styles.boxContent}>
          <div className= {styles.rowOne}>
            <div className= {styles.card}>
              <div className= {styles.cardBody}>
                <div className= {styles.cardHeader}>
                  <div className= {styles.cardContent}>
                    <h2>Current Spent this month</h2>
                   <div className= {styles.numbers}>
                    <p>$615</p>
                  </div>
                  </div>
                  <div className= {styles.moneySpent}>
                  <h2>You've spent 412 this month</h2>
                </div>
                </div>
                <p>Hi</p>
              </div>
            </div>
            <div className= {styles.card}>
              <div className= {styles.cardHeader}>
                <p>Recent Transactions</p>
                <p>You've had 12 transactions so far this month</p>
              </div>
              <div className= {styles.cardBody}>
              <div className = {styles.transactionHeader}>
                <h4>Date</h4>
                <h4>Name</h4>
                <h4>Amount</h4>
              </div>
              <div className= {styles.transactionButton}>
                <button className= {styles.transactionBtn}>
                  See More Transactions
                </button>
              </div>
              </div>
            </div>
          </div>
          <div className= {styles.accounts}>
            <div className= {styles.accountsCards}>
              <div className= {styles.accountsHeader}>
               <p>Accounts</p>
               <p>Synced 19 hours ago</p>
               <p>
                <a href = "">
                Sync Now
                </a>
                </p>
                </div>
              <div className= {styles.cardBodyAccounts}>
               <div className= {styles.cardBodyContainer}>
                <h1>Checking</h1>
               </div>
              </div>
            </div>
            <div className= {styles.cardBodyUpcoming}>
            <p>Coming Up</p>
          </div>
          <div className= {styles.cardsBodyUpcomingContainer}>
            <h1>Hi</h1>
          </div>
          </div>
        </div>
      </div>
     </div>
    </div>

    
    </>
    )
}

export default Dashboard