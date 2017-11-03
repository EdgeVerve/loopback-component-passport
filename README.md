# LoopBack Passport Component

This project is modification of original [loopback project](https://github.com/strongloop/loopback-component-passport).

This project is changed from original project for
* sending accesstoken as part of response cookie
* passing req.callContext as options parameter while making calls to loopback-datasource-juggler's dao.js methods. (eg findById, findOne)

**Note** : Test cases may not work.

## Please visit [loopback project](https://github.com/strongloop/loopback-component-passport) for original documentation.
> Please see the [official documentation](http://docs.strongloop.com/pages/viewpage.action?pageId=3836277) for more information.

## Support SAML and ADFS
SAML and ADFS is also supported and tested now.
SAML does post on callback URL post login
SAML does not pass profile.id field like google, facebook etc.
A new option profileIdAttribute is given now, which can be set to email or any other field to act as profile ID field.
For local SAML IDP server you can use [saml-idp](https://github.com/mcguinness/saml-idp)


## Profile to User Mapping
A new section userProfileMap can be given in providers.json to map profile to user
In providers.json you can specify

```
"userProfileMap": {
    "username" : "user"
    "email" : "emailID"
}
```

in case of adfs it can be 

```
"userProfileMap": {
    "email" : "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "username":""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", 
    "displayName" : "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
    "firstName" : "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
}
```




