# RoquiSigner
Is a signer application of the XML files using XAdES-BES algorithm

## Thanks
Thanks for XAdES4j project https://github.com/luisgoncalves/xades4j

## Description
The application is used for sign invoice, retention receipts, debit notes,
credit notes, remission guides and purchase liquidation for Ecuador country

## Software
* Java 21
* Gradle 8.11.1

## Warning
Before of continuing, please read the documentation, read the all documents in doc folder

## Gradle
### Upgrade Gradle
```
gradle wrapper --gradle-version 8.11.1
```

### Displays the tasks runnable from root project
```
gradle tasks
```
### Run
```
gradle run
```
### Test
```
gradle test
```
### Build
```
gradle build
```
## Publish in local maven repository
```
mvn install:install-file -Dfile=./app/build/libs/RoquiSigner-1.0.0.jar -DgroupId=dev.joguenco.signer -DartifactId=RoquiSigner -Dversion=1.0.0 -Dpackaging=jar
```

