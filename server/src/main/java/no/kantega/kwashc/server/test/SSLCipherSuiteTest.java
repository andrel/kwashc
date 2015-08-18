/*
 * Copyright 2012 Kantega AS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package no.kantega.kwashc.server.test;

import no.kantega.kwashc.server.model.Site;
import no.kantega.kwashc.server.model.TestResult;

import javax.net.ssl.SSLHandshakeException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;


/**
 * Test if SSL/TLS based communication allows insecure/weak ciphers and supports the best available Perfect Forward
 * Secrecy ciphers.
 *
 * Oracle has done a good job in disabling bad/weak ciphers in recent versions. Unfortunately that makes testing for
 * them a bit harder. To do this we need to override some settings in JDK_HOME/lib/security/java.security. To make this
 * work properly we need to start the server using jetty:run-forked. Alternatively this could have been done using
 * MAVEN_OPTS="-Djava.security.properties=jvm/java.security" mvn jetty:run.
 *
 * The actual test goes as follows:
 *
 * 1. Checks for availability of insecure, anonymous, weak ciphers
 * 2. Checks if Perfect Forward Secrecy ciphers with key length less then 1024 are present.
 * 3. Checks if the best Forward Secrecy ciphers are available.
 *
 * Solution, part 1:
 *
 * Exclude the following ciphers
 *
 * <excludeCipherSuites>
 * <excludeCipherSuite>SSL_RSA_WITH_3DES_EDE_CBC_SHA</excludeCipherSuite>
 * <excludeCipherSuite>SSL_DHE_RSA_WITH_DES_CBC_SHA</excludeCipherSuite>
 * <excludeCipherSuite>SSL_DHE_DSS_WITH_DES_CBC_SHA</excludeCipherSuite>
 * <excludeCipherSuite>SSL_RSA_WITH_NULL_MD5</excludeCipherSuite>
 * <excludeCipherSuite>SSL_RSA_WITH_NULL_SHA</excludeCipherSuite>
 * <excludeCipherSuite>SSL_RSA_WITH_RC4_128_SHA</excludeCipherSuite>
 * <excludeCipherSuite>SSL_RSA_WITH_RC4_128_MD5</excludeCipherSuite>
 * <excludeCipherSuite>SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA</excludeCipherSuite>
 * <excludeCipherSuite>SSL_DH_anon_EXPORT_WITH_RC4_40_MD5</excludeCipherSuite>
 * <excludeCipherSuite>TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5</excludeCipherSuite>
 * <excludeCipherSuite>TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA</excludeCipherSuite>
 * <excludeCipherSuite>TLS_DH_anon_WITH_AES_128_GCM_SHA256</excludeCipherSuite>
 * <excludeCipherSuite>TLS_ECDHE_ECDSA_WITH_RC4_128_SHA</excludeCipherSuite>
 * <excludeCipherSuite>TLS_ECDHE_RSA_WITH_RC4_128_SHA</excludeCipherSuite>
 * <excludeCipherSuite>TLS_ECDH_ECDSA_WITH_RC4_128_SHA</excludeCipherSuite>
 * <excludeCipherSuite>TLS_ECDH_RSA_WITH_RC4_128_SHA</excludeCipherSuite>
 * </excludeCipherSuites>
 *
 * Solution, part 2:
 *
 * Make sure there are all TLS_DHE_DSS_WITH* based ciphers are excluded.
 *
 * Solution, part 3:
 *
 * Make sure only Perfect Forward Secrecy ciphers with key length of > 1024 are available.
 *
 * Referanses:
 * <p/>
 * http://wiki.eclipse.org/Jetty/Howto/CipherSuites
 * http://www.techstacks.com/howto/j2se5_ssl_cipher_strength.html
 * https://hc.apache.org/httpcomponents-client-ga/httpclient/examples/org/apache/http/examples/client/ClientCustomSSL.java
 * http://cephas.net/blog/2007/10/02/using-a-custom-socket-factory-with-httpclient/
 * https://blogs.oracle.com/java-platform-group/entry/java_8_will_use_tls
 * https://www.ssllabs.com/ssltest/viewClient.html?name=Java&version=8u31
 * server/cipher/*.txt: Full list of ciphers supported by different Java versions.
 *
 * @author Espen A. Fossen, (www.kantega.no)
 */
public class SSLCipherSuiteTest extends AbstractSSLTest {

    @Override
    public String getName() {
        return "SSL/TLS Connection Cipher Strength Test";
    }

    @Override
    public String getDescription() {
        return "Test if a weak Cipher is  allowed for an SSL/TLS connection.";
    }

    @Override
    public String getInformationURL() {
        return "https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet";
    }

    @Override
    protected TestResult testSite(Site site, TestResult testResult) throws Throwable {
        long startTime = System.nanoTime();

        int httpsPort;
        try {
            httpsPort = new Integer(site.getSecureport());
        } catch (NumberFormatException e) {
            testResult.setPassed(false);
            testResult.setMessage("No HTTPS port specified, test not run!");
            setDuration(testResult, startTime);
            return testResult;
        }

        try {

            String[] ciphers = new String[]{
                    "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
                    "SSL_DHE_RSA_WITH_DES_CBC_SHA",
                    "SSL_DHE_DSS_WITH_DES_CBC_SHA",
                    "SSL_RSA_WITH_NULL_MD5",
                    "SSL_RSA_WITH_NULL_SHA",
                    "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
                    "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5",
                    "SSL_RSA_WITH_RC4_128_SHA",
                    "SSL_RSA_WITH_RC4_128_MD5",
                    "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
                    "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
                    "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
                    "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
                    "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
                    "TLS_ECDH_RSA_WITH_RC4_128_SHA"
            };

            if (checkClient(site, httpsPort, new String[]{"TLSv1"}, ciphers) == 200) {
                testResult.setPassed(false);
                testResult.setMessage("Your application accepts weak/anonymous SSL/TLS cipher suites!");
            }

        } catch (NoSuchAlgorithmException e) {
            return exitMissingCipherSuites(testResult);
        } catch (KeyManagementException e) {
            return exitIncorrectCertificate(testResult);
        } catch (SSLHandshakeException e) {
            if (e.getMessage().contains("No appropriate protocol (protocol is disabled or cipher suites are inappropriate)")) {

                try {
                    String[] ciphers = new String[]{
                            "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                            "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
                            "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
                            "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"};

                    if (checkClient(site, httpsPort, new String[]{"TLSv1"}, ciphers) == 200) {

                        try {
                            String[] ciphers2 = new String[]{
                                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                                    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
                                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
                                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                                    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
                                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                                    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
                                    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
                                    "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
                            };

                            if (checkClient(site, httpsPort, new String[]{"TLSv1"}, ciphers2) == 200) {
                                testResult.setPassed(true);
                                testResult.setMessage("Top score, no weak/anonymous ciphers and supporting the best available Perfect Forward Secrecy ciphers are present.");
                            } else {
                                exitWrongHttpCode(testResult);
                            }
                            return testResult;
                        } catch (NoSuchAlgorithmException e1) {
                            return exitMissingCipherSuites(testResult);
                        } catch (KeyManagementException e1) {
                            return exitIncorrectCertificate(testResult);
                        } catch (IOException e1) {
                            testResult.setPassed(false);
                            testResult.setMessage("Almost there, no weak/anonymous ciphers and allows Perfect Forward Secrecy, but some of your ciphers require DSA keys, which are effectively limited to 1024 bits!");
                            return testResult;
                        }
                    } else {
                        exitWrongHttpCode(testResult);
                    }
                    return testResult;
                } catch (NoSuchAlgorithmException e1) {
                    return exitMissingCipherSuites(testResult);
                } catch (KeyManagementException e1) {
                    return exitIncorrectCertificate(testResult);
                } catch (IOException e1) {
                    testResult.setPassed(false);
                    testResult.setMessage("Looking better, your application does not allow SSL/TLS connection with anonymous/weak ciphers, but does not support Perfect Forward Secrecy!");
                    return testResult;
                }

            } else {
                testResult.setPassed(false);
                testResult.setMessage("Actual testing failed, check that the connection is working!");
            }
        } finally {

            setDuration(testResult, startTime);
        }

        return testResult;
    }

    private void exitWrongHttpCode(TestResult testResult) {
        testResult.setPassed(false);
        testResult.setMessage("The server did not respond with an HTTP 200 when it should, contact tutor.");
    }

    private TestResult exitIncorrectCertificate(TestResult testResult) {
        testResult.setPassed(false);
        testResult.setMessage("Certificate configuration does not seem to be correct, check certificate on remote environment!");
        return testResult;
    }

    private TestResult exitMissingCipherSuites(TestResult testResult) {
        testResult.setPassed(false);
        testResult.setMessage("Cipher suites used for connection not available in local environment, contact tutor.");
        return testResult;
    }

}
