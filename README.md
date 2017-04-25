# LoopBack Passport Component

This project is modification of original [loopback project](https://github.com/strongloop/loopback-component-passport).

This project is changed from original project for
* sending accesstoken as part of response cookie
* passing req.callContext as options parameter while making calls to loopback-datasource-juggler's dao.js methods. (eg findById, findOne)

**Note** : Test cases may not work.

## Please visit [loopback project](https://github.com/strongloop/loopback-component-passport) for original documentation.
> Please see the [official documentation](http://docs.strongloop.com/pages/viewpage.action?pageId=3836277) for more information.