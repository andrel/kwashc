# Kantega Web Application Security Hero Challenge (kwashc) #

## About ##

Developed for an in house training challenge for employees. The main goals with the challenge was to educate developers
about security risks for web applications.

The concept is to give all the participants the Java code for a simple blog implementation (webapp project). Then each
participant or team registers their blog application on the server. The server then tests a set of know security risks
against the application. While learning about security risks, the participant are challenged to fix them, with help
both from the test server and the ones holding the challenge. The first participant or team to have all risks fixed
wins.

Fixing a risk does not necessarily mean the risk is completely removed, as both test and fix might not be correctly
implemented. Either way the challenge tries to educate and create awareness about each risk, which is the most important
part of the challenge.

The security risks are mostly based on the [OWASP Top 10](https://www.owasp.org). list, but a few additional risks have
also been added.


## Requirements ##

__Server__

* Apache Maven 3.x
* JVM 6.x (7.x for all tests to work, see SSLProtocolTest for more info)
* Direct network connection to all clients
* Internet connection for downloading maven dependencies

__Clients__

* Apache Maven 3.x
* JVM 6.x (7.x for all tests to go green, but let the participants find out themselves, see SSLProtocolTest for more info)
* A decent IDE, like IDEA, Eclipse
* Internet connection for downloading maven dependencies


## Usage ##

Build and run server

        mvn clean install
        cd server
        mvn jetty:run

Build and run client

        cd webapp
        mvn clean install jetty:run


## Credits ##

    Anders B�tstrand   idea, framework and tests
    Espen A. Fossen    framework and additional tests
    �ystein �ie        framework and additional tests
    Frode Standal      additional tests
    Espen Hjert�       web design


## Contact ##

For ideas, suggestions or other non spam inquiries:

    anders at kantega dot no
    espenaf at kantega dot no
