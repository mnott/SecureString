package com.sap.securestring.tests;

import com.sap.securestring.SecureString;

import static org.junit.Assert.*;

import org.junit.Test;

import org.junit.runner.RunWith;

import org.junit.runners.Parameterized.Parameters;

import java.util.ArrayList;
import java.util.List;


@RunWith(Parallelized.class)
public class TestSecureString {
  private String parameter;

  public TestSecureString(String parameter) throws Exception {
    this.parameter = parameter;
  }

  @Parameters(name = "{index}: {0}")
  public static Iterable<String[]> parameters() {
    final List<String> parameters = new ArrayList<String>();

    /*
     * Add your parameters here
     */
    parameters.add("x|5500");
    parameters.add("y|500");
    parameters.add("z|15500|true");
    parameters.add("a");
    parameters.add("y");

    /*
     * Transferring parameters
     */
    List<String[]> results = new ArrayList<String[]>(parameters.size());
    for (String parameter : parameters) {
      results.add(new String[] { parameter });
    }

    return results;
  }


  /**
   * Test
   *
   * Implement your test here.
   *
   * You are handed one parameter as field.
   */
  @Test public void test() throws Exception {
    final String[] pars     = StringUtility.split(this.parameter, "|");

    /*
     * Find out whether we want to assign a lifetime
     */
    int            lifetime = -1;

    if (pars.length > 1) {
      lifetime = StringUtility.StringToInteger(pars[1], -1);
    }

    /*
     * Find out whether we want to hash the String
     */
    boolean hashed = false;

    if (pars.length > 2) {
      hashed = "true".equals(pars[2]);
    }

    /*
     * Create the String. There are other constructors, too.
     */
    final SecureString s = new SecureString(pars[0], lifetime, hashed);

    /*
     * Play with the properties
     */
    s.setDebug(true);
    s.setUpdateInterval(1000); // just because we can.

    /*
     * Print out a first statement
     */
    System.out.println("Start     : Original Value " + pars[0] + ", " + s.status());

    /*
     * Get a String representation of the SecureString;
     * if it was asked to be hashed, we are going to get
     * a hash at this point; otherwise we're going to get
     * the String. Or, of course, if our interval was too
     * short, we're going to get an empty string already.
     * We could also use the public md5 function of that
     * SecureString.
     */
    final String  ourString = s.toString();

    /*
     * Do the comparison.
     */
    final boolean eq1       = s.equals(ourString);

    /*
     * Should be equal at this point.
     */
    assertTrue(eq1);

    /*
     * Now, if we're actually waiting, we monitor that process, too.
     */
    if (lifetime > 0) {
      /*
       * So first we wait like half the lifetime of our String
       */
      try {
        Thread.sleep(lifetime / 2);
      } catch (InterruptedException ie) {}

      /*
       * Then we get a new test to see whether the
       * SecureString still is the same. If the
       * interval was too short, we could fail at
       * this point.
       */
      final boolean eq2 = s.equals(ourString);
      System.out.println("Half time : Original Value " + pars[0] + ", " + s.status());

      assertTrue(eq2);

      /*
       * Now we wait some more, and yes, we add some
       * random margin to compensate for your slow
       * laptop.
       */
      try {
        Thread.sleep((lifetime / 2) + 1500 /* Some margin */);
      } catch (InterruptedException ie) {}

      /*
       * Now, as we have an expiring SecureString,
       * what we get here should no longer be equal.
       */
      final boolean eq3 = s.equals(ourString);
      System.out.println("Finish    : Original Value " + pars[0] + ", " + s.status());

      assertFalse(eq3);
    }
  }
}
