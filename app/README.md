# Project Title

## POST /signup/registration
- Used for registering new users
- expection from client is a json body
    {
        "firstname":"Jamo",
        "lastname": Aphrodisu",
        "email" : "abraham@trendsaf.com",
        "password": "12345"
    }
- Expected Server Responses
    if any of the expected json is missing parameter 
        `{
            "error": 422,
            "message": "missing parameter",
            "status": false
        }`
    
    if email is with the wrong format
        {
            "message": "invalid email"
        }
    If email exists already
        {
            "exists": true,
            "is_verified": false,
            "message": "Account with email already exists"
        }
    For a successfull registration
        {
            "id": "IjAyMjQwNDJmLTBhNjItNDI5YS1hM2E1LWI5ZTUyODNlNTY4NiI.4u8HnVUIzqT0Feh334fX2XX28lo",
            "is_confirmed": false,
            "is_verified": false,
            "message": "Registration successful",
            "status": 200
        }
    On successfull registration a verification link will be sent to the user's email 


## 2. On clicking verification link in email

    On success, redirects to {http://46.101.27.66:5001/verify_user?message=success}

    On error, {'http://46.101.27.66:5001/verify_error?message=link has been used'} or {'http://46.101.27.66:5001/verify_error?message=link has expired'}\
    verify_error page should have a form for resending link 

    Note: the success or error messages are the params in the link


## 3. POST  signup/link_resend
- Expected from client
    {
        "email" : aphrodis@gmail.com
    }

- Expected Server Response

    If wrong request method is used
    `{
        "error": 405,
        "message": "api call method not permitted",
        "status": false
    }`

    If request email doesn't exist
    `
    {
        "status" : False,
        "message" : "email not registered"
    }
    `
- On successful link resend
    `{
            "status": True,
            "message": "Verification link sent"
    }`

## 4. POST /auth/confirmation
- Used to confirm the user and add user profile

- Expectations from client
    Authorization Header
    {
        Bearer Token
    }
    -H {
        "X-CSRF-TOKEN": "value of the cookie access_token"
    }

- On the body of the request, implement the following
replace the null values with your form values
     {
        "company_name" : "",
        "company_type": "",
        "company_size": "",
        "start_year": "",
        "annual_revenue": "",
        "company_role": "",
        "phone": "",
        "province": "",
        "country": "",
    }



## 5. POST /auth/login
- Used for authenticating users
- Expectation from client
    A json is appended to the body of  the request
    {
       "email" : "apercu@trendsaf.com",
       "password" : "12345" 
    }


- Expected Server Responses 
- If user doesn't exist or wrong password
    {
        "status": False
        "message": "wrong email or password"
    }
-  On successfull authentication but not verified..
    `
    {
        "status": False,
        "message": "Verification link sent"
    }
    `
-  On successfull authentication and verified.. 
    {
        "status": true,
        "is_confirmed": false,
        "is_verified": true,
        "message": "Not verified"
    }

    On successfull authentication, verification and confirmation.. Remember to redirect the user to the confirmation page if is_confirmed is False

    {
        "status": True,
        "is_verified": True,
        "is_confirmed": True,
        "user_role" : "",
        "company_name": "",
        "company_type" : "",
        "company_size" : "",
        "start_year": "",
        "province" : "",
        "access_token": "",
        "csrf_token": ""
    }

    Note: the status parameter is the primary parameter


## 6. /auth/password_reset_request
- Used for requesting password reset

- Expected request from client
    {
        "email":"nhamo@trendsaf.co"
    }

- Expected Server Responses all things being equal
    If user does not exist
    {
        "message": "User does not exit",
        "status": false
    }

    If user exists and mail is sent successfully.... Remember to let the user know that the email link last for just 15 minutes
    `{
        "status": True,
        "message": "password link sent"
    }`

## 7. /auth/password_reset/<token>
- Used for requesting password reset

- Expected request from client

    Add the token from the url as a parameter

    {
        "password": "123456789"
    }

-  Expected Server Responses
    On successful password reset
    {
        "message": "password changed successfully",
        "status": true
    }

    On unsuccessful password reser
    `
    {
        "status" : False,
        "message": "password change is unsuccessful"
    }
    `