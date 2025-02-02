SEMGREP RULE

rules:
  - id: des-is-deprecated
    patterns:
      - pattern-either:
        - pattern: >
            String $STRING = benchmarkprops.getProperty("...","...");
            javax.crypto.Cipher $X = javax.crypto.Cipher.getInstance($Y);
        - pattern: >
            String $STRING = benchmarkprops.getProperty("...","...");
            String unused = "..."
            javax.crypto.Cipher $X = javax.crypto.Cipher.getInstance($Y);
      - pattern-not: >
          String $STRING = benchmarkprops.getProperty("...","AES/CBC/PKCS5Padding");
          javax.crypto.Cipher $X = javax.crypto.Cipher.getInstance($Y);
    message: >
      DES is considered deprecated. AES is the recommended cipher.
      Upgrade to use AES.
      See https://www.nist.gov/news-events/news/2005/06/nist-withdraws-outdated-data-encryption-standard for more information.
    languages:
      - java
    severity: WARNING



CODE TO RUN AGAINST

    package servlets;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class Cls extends HttpServlet
{  
    protected void danger(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        java.util.Properties benchmarkprops = new java.util.Properties();
        
        // match this
        String desAlgorithm = benchmarkprops.getProperty("cryptoAlg1", "DES/ECB/PKCS5Padding");
        javax.crypto.Cipher c1 = javax.crypto.Cipher.getInstance(desAlgorithm);
        
        // match this
        String algo = benchmarkprops.getProperty("cryptoAlgX", "DES/ECB/PKCS5Padding");
        javax.crypto.Cipher cc = javax.crypto.Cipher.getInstance(algo);

        // don't match this
        String aesAlgorithm = benchmarkprops.getProperty("cryptoAlg2", "AES/CBC/PKCS5Padding");
        javax.crypto.Cipher c2 = javax.crypto.Cipher.getInstance(aesAlgorithm);

        // match this
        String alg = benchmarkprops.getProperty("cryptoAlgo", "DES/CBC/PKCS5Padding")
        String unused = "hello world"
        javax.crypto.Cipher cc2 = javax.crypto.Cipher.getInstance(alg);
    }
} 