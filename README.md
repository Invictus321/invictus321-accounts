# invictus321-accounts
Secure account management library for web applications

## Setup

Set up your database, and run the sql under db/schema

Set ACCOUNTS_DATABASE_URL to your database (postgres://username:password@url:port/database_name?sslmode=disable)

Run 'go test --tags integration' to make sure your db is working

Good to go

## Usage

Create the service: 

as := accounts.ServiceFromEnv(secret, encryptionKey, lifespan)

Where secret is your token secret (can be any string, as long as it is always the same)

encryptionKey is your 32-character key for encryption

And lifespan is how many seconds you want your user tokens to remain valid

## API

as.CreateUser(id, password) - Creates a new user and returns the token for that user

as.Login(id, password) - Checks the password and if correct, returns the token for the user

as.Authorise(token) - Checks if the token is valid and not expired, and if so, returns the user's id

as.DeleteUser(id) - Deletes a user by id

as.ChangePassword(token, password) - Changes the user password

## How it works

A user accessing your system sends you their user id and password, you use the as.CreateUser(id, password) to create their account, or as.Login(id, password) function to check their password, and then return the resulting token to the user. 

For all following requests from the user, they should pass their token to you. Before servicing their requests, you use as.Authorise() to check if their token is valid, and if it matches their user id.

Tokens will expire and no longer authenticate once the lifeSpan you specify has passed.