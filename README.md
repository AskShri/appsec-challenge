
Hi there,

Firstly congratulation on making it so far in the interview process. We love that you want to join us and make Application Security a better story at Xero. We wish you all the best for this challenge.

As the next step in our interview process for the Application Security role, we would like to see your hands-on approach to building secure by design application security features.

Instead of a standard audit, this challenge focuses on **security engineering**: your ability to implement defensive measures within a functional login system.

---
## The Scenario

We are launching a new internal portal, and you have in this folder the beginnings of a login form. However, it currently lacks the necessary security measures to protect against common authentication based attacks. 

You are free to choose a development language, framework and/or tools of your choosing to complete this challenge. You are also free to use any AI assisted coding tools. However, if you do so, we require you to let us know what AI service and subsequent models were used during the completion of this project. 

**Your goal:** Enhance the existing login form to meet modern security standards.

## Your Tasks

You are tasked with implementing defenses against authentication based attacks. The following are some examples of measures that you may consider. These are neither mandatory nor comprehensive. You will use your expertise and experience to make a risk based decision balancing security controls vs the usability of the login form vs the time and resources you have at your disposal. :

1. Rate Limiting & Brute Force Protection to prevent credential stuffing and brute force attacks.
2. Secure Session Management to follow best practices (e.g., HttpOnly, Secure, SameSite, etc. flags) when setting session cookies and/or implement a secure "Logout" functionality that properly invalidates sessions server-side.
3. HTTP oriented security response headers (e.g., X-Frame-Options, Content-Security-Policy) specifically tailored to protect the login page from clickjacking and XSS.

## Evaluation Criteria

We will evaluate your submission based on:

- Defense in Depth: How well your features overlap to protect the user's identity.
- Code Logic: Is the security logic clean, well-commented, and easy for other developers to maintain?
- User Experience: Do the security measures provide helpful feedback without leaking sensitive information (e.g., "User not found" vs. "Invalid credentials")? Do the security measures hinder usability of the form.
- Design Decisions: Your choice of measures you decided to implement in the short period of time you had. 

## Submission Instructions

- Please submit your updated code via a Pull Request (PR) on a public Github repository or a zip file.
- Include a **SUBMISSION.md** file explaining providing context to your submission with insights into your design decisions and measures selection. 
- We recommend you spend not more than **3–4 hours** on completing this challenge. You have 7 days to complete this challenge and return the submission back to your interview contact. 

We’re excited to see how you approach this challenge and hope to speak to you soon.

Best regards,

The Application Security Team @ Xero

