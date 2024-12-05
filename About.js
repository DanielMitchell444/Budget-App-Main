import React from "react";
import styles from '../Styles/App.module.css'

const About = () => {
  return(
  <div className= {styles.wrappedContainer2}>
    <div className= {styles.features}>
   <h1>About Us</h1>
   <p>Started in 2020 out of our small office in Milan, Italy, Echo was created with a single mission: to make budgeting easier and more accessible for everyone. Teaming up with financial experts, developers, and designers, we’ve built an intuitive app that empowers users to take control of their finances with ease and confidence.</p>
   <p>From automatic expense tracking to real-time budget updates, every feature is designed to help you manage your money efficiently. Echo’s goal is to simplify the process of budgeting, providing you with the tools to save smarter and achieve your financial goals.</p>
   <p>To make this happen, we’ve worked closely with trusted fintech partners to ensure that the app’s technology is secure, reliable, and user-friendly. We continuously improve the app by learning from the best in the industry, ensuring that Echo remains a cutting-edge tool for personal finance management. (read more on Our Features)</p>
   <p>At Echo, we believe budgeting should be stress-free and empowering. With our app, we help you track spending, set achievable goals, and stay on top of your finances every step of the way</p>
   </div>
   <div className= {styles.mission}>
    <h1>Our Mission</h1>
    <p>At Echo, we believe in providing a truly personalized approach to managing your finances. Our direct-to-user model ensures that everything we build is focused on delivering exactly what you need, without compromise. Whether it’s tracking your spending or setting financial goals, Echo adapts to your unique needs and priorities, minimizing unnecessary complexity or wasteful features. And we do this at an honest price, because smart money management shouldn’t be a luxury. (read more on Our Approach and Ethical Finance)</p>
    <p>Start now with our core budgeting tools that we’ve designed to help you manage your money effectively. Our core features, such as automatic expense tracking and goal setting, are always available to help you stay on top of your financial situation. However, if you're looking for something more tailored to your needs, we also offer premium features and personalized settings that can be activated as you need them. You can customize your financial dashboard or adjust alerts and reminders to ensure that Echo works exactly the way you want it. (read more on Premium Features)</p>
    <p>For those who want a truly unique experience, our Custom Finance Plans are the answer. With our tailored budgeting tools, you can customize Echo’s features to suit your personal financial goals — from debt reduction plans to investment tracking. Whether you want to set up a personalized savings plan or receive expert insights, we’ve got you covered. Contact us for an online consultation to get started with your custom financial plan and experience everything Echo has to offer. (read more on Custom Plans)</p>
   </div>
   <div className= {styles.keyFeatures}>
    <h1 id = {styles.features2}>Key Features</h1>
    <div className= {styles.featuresContainer}>
    <div className= {styles.featuresBox}>
     <div className= {styles.featureText}>
        <h1>Automatic Expense Tracking & Syncing</h1>
        <p id = {styles.text}>Echo automatically syncs with your bank accounts, credit cards, and payment platforms to categorize your transactions in real-time. This helps you effortlessly track your spending and stay on top of your finances without manual input.</p>
     </div>
    </div>
    <div className= {styles.featuresContainer}>
    <div className= {styles.featuresBox}>
     <div className= {styles.featureText}>
        <h1>Personalized Budgeting & Goal Setting</h1>
        <p id = {styles.text}>With Echo, you can easily set up custom budgets for different categories,and track your progress. The app also allows you to set specific financial goals, such as saving for a vacation or paying off debt, and provides insights on how to reach them faster.</p>
     </div>
    </div>
    <div className= {styles.featuresContainer}>
    <div className= {styles.featuresBox}>
     <div className= {styles.featureText}>
        <h1>Smart Insights & Financial Health Report</h1>
        <p id = {styles.text}>Echo offers personalized insights based on your spending habits and provides regular financial health reports. The app helps you identify areas where you can save more, spend less, and optimize your financial strategy, so you can make smarter decisions with your money.</p>
     </div>
    </div>
    </div>
   </div>
  </div>
  </div>
  </div>
  )
}

export default About