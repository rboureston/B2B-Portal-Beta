## B2B Portal Beta
This is the application that runs the Sign-In Widget Beta Portal. 

## Running the Application

* Make sure you have a file in your home directory with Okta settings as shown
```
cat ~/.okta/okta.yaml 
okta:
  idx:
    clientId: <Your client ID>
    clientSecret: <Your client Secret>
    issuer: https://<Okta-Tenant>.oktapreview.com/oauth2/default
    redirectUri:  <Your redirect URL>
    scopes:
      - openid
      - profile
  ```

* Clone the repo
```
  git clone dmahalingam-okta/siw-beta-portal
  cd beta
```

* Run the App
```
go run main.go
```

Go to http://localhost:8000 to see the site
