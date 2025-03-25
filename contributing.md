# How to contribute
To contribute you need to fork the repository to your account, implement changes and create pull request.

## How to test
The test case for these are written for keycloak and auth0 so first you need to download and install keycloak
from [here](https://www.keycloak.org/downloads).

Also, you need to set up private and public keys and export it as environment variables `privateKey` and `publicKey`

**Note:** you can avoid auth0 tests cases by renaming it to `DefaultAuth0SSOAndCertsClassTestIgnore` and `DefaultAuth0SSOTestIgnore`

Once you install keycloak create 2 realms in it `Testing` and `Testing-2`.
inside each realm create client `test-app` and create user with username and password as `test-user`, `12345`.

and now run `mvn test` or `mvn clean install`
