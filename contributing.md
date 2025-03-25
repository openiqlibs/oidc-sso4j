# How to contribute
To contribute you need to fork the repository to your account, implement changes and create pull request.

## How to test
The test case for these are written for keycloak and auth0 so first you need to download and install keycloak
from [here](https://www.keycloak.org/downloads).

**Note:** you can avoid auth0 test case by renaming it to

Once you install keycloak create 2 realms in it `Testing` and `Testing-2`.
inside each realm create client `test-app` and create user with username and password as `test-user`, `12345`.

and now run `mvn test` or `mvn clean install`
