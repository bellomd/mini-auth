# MINI AUTH #

As the name implies, it's for token generation and manipulation. There are bunch of different functions
for different ways of generating, parsing and validation of token for your application authentication.
For every token bee it jwt, oauth2 or ordinary token generation method, filters (middleware) are provided 
that will handle the request and validate the authenticity of the header or context provided token.

Environment variable are provided in constant.go, they can be edited base on your need.  Also, the
LoadEnvironmentVariables function in auth_util.go should be called at the start of your application
or in the main function of your application if you want to work with defaults for all the environment variables.

## WORK IN PROGRESS ##

For now the project is a work in progress, only the jwt part is completed and usable.

### FUNCTIONALITIES OF THE PROJECT ###

* JWT TOKEN GENERATION (added)
* OAUTH2 TOKEN GENERATION (to be added)
* ORDINARY TOKEN GENERATION (to be added)


# LICENSE #

[MIT](https://github.com/bellomnk/mini-auth/blob/master/LICENSE)