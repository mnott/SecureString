package com.sap.securestring;

import java.io.UnsupportedEncodingException;

import java.nio.charset.Charset;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.util.Calendar;
import java.util.Date;


public class SecureString {
  /**
   * Internal char[] representation of the
   * String or its hash.
   */
  private char[]        string;

  /**
   * The Updater Thread.
   */
  private StringUpdater updater        = null;

  /**
   * Update interval for the String, in milliseconds.
   */
  private long          updateInterval = 1000;


  /**
   * The creation time for the Object.
   */
  private Date          creationTime   = new Date();

  /**
   * The expiry time for the Object.
   */
  private Date          expiryTime     = new Date();

  /**
   * Whether or not an object may life forever. Creating a String with a
   * lifetime < 0 will leave the string forever.
   */
  private boolean       livesForever   = false;

  /**
   * The actual lifetime of the object.
   */
  private long          lifeTime       = -1;


  /**
   * Whether the updater thread was started.
   * The updater thread should only be started
   * if there are any entries that have a timeout.
   */
  private boolean       updaterStarted = false;


  /**
   * Set to true to get some output.
   */
  private boolean       debug          = false;

  /**
   * Whether the string was hashed.
   */
  private boolean       hashed         = false;


  /**
   * Encoding to use.
   */
  private Charset       charset        = Charset.forName("UTF-8");


  /**
   * The default constructor is just there.
   * Maybe we do some more work here at some
   * point in our life.
   */
  public SecureString() {}


  /**
   * If we pass a String, we convert it into
   * char array, but we do assume this then
   * lives forever.
   *
   * It uses the UTF-8 character set.
   *
   * @param str The string.
   */
  public SecureString(String str) {
    this();
    this.livesForever = true;
    this.hashed       = true;
    this.string       = hash(str);
  }


  /**
   * If we pass a String, we convert it into
   * char array, but we do assume this then
   * lives forever.
   *
   * @param str The string.
   * @param charset The character set.
   */
  public SecureString(String str, String charset) {
    this();
    this.charset      = Charset.forName(charset);
    this.livesForever = true;
    this.hashed       = true;
    this.string       = hash(str);
  }


  /**
   * If we pass a lifetime, we also want to
   * have some concurrent thread check whether
   * that string should still survive down the
   * road.
   *
   * It uses the UTF-8 character set.
   *
   * @param str The string.
   * @param lifetime The lifetime.
   */
  public SecureString(String str, long lifetime) {
    this();
    this.hashed = true;
    this.string = hash(str);
    if (lifetime >= 0) {
      this.updater = new StringUpdater();
      this.updater.setDaemon(true);
      this.updater.setParent(this);
      //this.updater.start(); // not until string expires
      this.livesForever = false;
      this.expiryTime.setTime(Calendar.getInstance().getTime().getTime() + (lifeTime * 1000));
      startUpdater();
    }
  }


  /**
   * If we pass a lifetime, we also want to
   * have some concurrent thread check whether
   * that string should still survive down the
   * road.
   *
   * @param str The string.
   * @param charset The character set.
   * @param lifetime The lifetime.
   */
  public SecureString(String str, String charset, long lifetime) {
    this();
    this.charset = Charset.forName(charset);
    this.hashed  = true;
    this.string  = hash(str);
    if (lifetime >= 0) {
      this.updater = new StringUpdater();
      this.updater.setDaemon(true);
      this.updater.setParent(this);
      //this.updater.start(); // not until string expires
      this.livesForever = false;
      this.expiryTime.setTime(Calendar.getInstance().getTime().getTime() + (lifeTime * 1000));
      startUpdater();
    }
  }


  /**
   * If we want to hash the String, we can do so.
   *
   * It uses the UTF-8 character set.
   *
   * @param str The string.
   * @param hashed Whether to keep it hashed.
   */
  public SecureString(String str, boolean hashed) {
    this();
    this.livesForever = true;
    this.hashed       = hashed;
    if (hashed) {
      this.string = hash(str);
    } else {
      this.string = str.toCharArray();
    }
  }


  /**
   * If we want to hash the String, we can do so.
   *
   * @param str The string.
   * @param charset The character set.
   * @param hashed Whether to keep it hashed.
   */
  public SecureString(String str, String charset, boolean hashed) {
    this();
    this.charset      = Charset.forName(charset);
    this.livesForever = true;
    this.hashed       = hashed;
    if (hashed) {
      this.string = hash(str);
    } else {
      this.string = str.toCharArray();
    }
  }


  /**
   * Finally, a string can not only have a lifetime,
   * but also be hashed for the paranoid among us.
   *
   * It uses the UTF-8 character set.
   *
   * @param str The string.
   * @param lifetime The lifetime.
   * @param hashed Whether to keep it hashed.
   */
  public SecureString(String str, long lifetime, boolean hashed) {
    this();
    this.lifeTime = lifetime;
    if (lifetime >= 0) {
      this.updater = new StringUpdater();
      this.updater.setDaemon(true);
      this.updater.setParent(this);
      //this.updater.start(); // not until string expires
      this.livesForever = false;
      this.expiryTime.setTime(Calendar.getInstance().getTime().getTime() + (lifetime));
      startUpdater();
    }

    this.hashed = hashed;
    if (hashed) {
      this.string = hash(str);
    } else {
      this.string = str.toCharArray();
    }
  }


  /**
   * Finally, a string can not only have a lifetime,
   * but also be hashed for the paranoid among us.
   *
   * @param str The string.
   * @param charset The character set.
   * @param lifetime The lifetime.
   * @param hashed Whether to keep it hashed.
   */
  public SecureString(String str, String charset, long lifetime, boolean hashed) {
    this();
    this.charset  = Charset.forName(charset);
    this.lifeTime = lifetime;
    if (lifetime >= 0) {
      this.updater = new StringUpdater();
      this.updater.setDaemon(true);
      this.updater.setParent(this);
      //this.updater.start(); // not until string expires
      this.livesForever = false;
      this.expiryTime.setTime(Calendar.getInstance().getTime().getTime() + (lifetime));
      startUpdater();
    }

    this.hashed = hashed;
    if (hashed) {
      this.string = hash(str);
    } else {
      this.string = str.toCharArray();
    }
  }


  /**
   * Get a quick status.
   *
   * @return Status.
   */
  public String status() {
    final StringBuffer sb = new StringBuffer();

    sb.append("Value: " + this);
    sb.append(", Creation Time: " + this.creationTime);
    sb.append(", Expiry Time: " + this.expiryTime);
    sb.append(", Expired: " + expired());

    return sb.toString();
  }


  /**
   * Set to debug mode.
   *
   * @param debug true to debug.
   */
  public void setDebug(boolean debug) {
    this.debug = debug;
  }


  /**
   * Get the Update Interval in ms.
   *
   * @return The Update Interval in ms.
   */
  public long getUpdateInterval() {
    return this.updateInterval;
  }


  /**
   * Set the Update Interval in ms.
   *
   * @param updateInterval the Update Interval in ms.
   */
  public void setUpdateInterval(long updateInterval) {
    this.updateInterval = updateInterval;
  }


  /**
   * Check whether string was hashed
   *
   * @return true if hashed, else false
   */
  public boolean isHashed() {
    return this.hashed;
  }


  /**
   * Some quick'n'dirty fail-early equals.
   *
   * If we are hashing, we're expecting
   * the parameter to be a hash as
   * produced by our hash function.
   *
   * @param with To compare with.
   * @return True if equals, else false.
   */
  public boolean equals(String with) {
    final char[] b = with.toCharArray();

    final int    l = b.length;

    if (this.string == null) {
      return false;
    }

    final char[] a = this.hashed ? this.toString().toCharArray() : this.string;

    if (a.length != l) {
      return false;
    }

    for (int i = 0; i < l; i++) {
      try {
        if (a[i] != b[i]) {
          return false;
        }
      } catch (ArrayIndexOutOfBoundsException e) {
        // concurrent modification setting to 0
        return false;
      }
    }

    return true;
  }


  /**
   * Destroy the string and stop the update thread. Call this method when the
   * string is no longer needed, to avoid wasting memory and cpu time. If you
   * attempt to use the string after calling the destroy method, a null pointer
   * exception will be thrown.
   */
  public synchronized void destroy() {
    if (this.debug) {
      System.out.println("Destroying: " + new Date() + " " + this.expired());
    }

    if (this.string != null) {
      final int l = this.string.length;
      for (int i = 0; i < l; i++) {
        string[i] = '\0'; // kidding
      }

      string = new char[0];
    }

    try {
      this.updater.setActive(false);
      this.updater.setDaemon(false);
      this.updater.interrupt();
      this.updater = null;
    } catch (IllegalThreadStateException e) {}
  }


  /**
   * Some hash function.
   *
   * @param str
   * @return The hashed for the string.
   */
  public char[] hash(String str) {
    return SecureString.hash(str, this.charset);
  }


  /**
   * Some hash function.
   *
   * @param str
   * @param charset The character set. If you want to use this function,
   * you can create the character set like
   * <pre>
   *   final java.nio.charset.Charset charset = Charset.forName("UTF-8");
   * </pre>
   * @return The hashed for the string.
   */
  public static char[] hash(String str, Charset charset) {
    try {
      final MessageDigest md = MessageDigest.getInstance("SHA-512");
      md.update(str.getBytes(charset));

      final byte[] hash   = md.digest();
      final int    l      = hash.length;
      final char[] result = new char[l];
      for (int i = 0; i < l; i++) {
        result[i] = (char) hash[i];
      }

      return result;
    } catch (NoSuchAlgorithmException e) {
      System.err.println("! Caught Exception: " + e.getMessage());
    }

    return new char[0];
  }


  /**
   * A toString that re-encodes the char
   * array into a String, and if it was
   * hashed, generates some hex string.
   */
  public synchronized String toString() {
    if (this.string == null) {
      return "";
    }

    if (this.hashed) {
      final StringBuffer hexString = new StringBuffer();
      final int          l         = this.string.length;
      for (int i = 0; i < l; i++) {
        if ((0xff & this.string[i]) < 0x10) {
          hexString.append("0" + Integer.toHexString((0xFF & this.string[i])));
        } else {
          hexString.append(Integer.toHexString(0xFF & this.string[i]));
        }
      }

      return hexString.toString();
    }

    return new String(this.string);
  }


  /**
   * Start the updater thread. This should only
   * be done if the string expires,
   * i.e. it has a lifetime >=0.
   */
  private void startUpdater() {
    if (!this.updaterStarted) {
      updater.start();
      this.updaterStarted = true;
    }
  }


  /**
   * Get the lifetime for the object in the cache.
   *
   * @return The lifetime, in milliseconds.
   */
  protected long getLifeTime() {
    return this.lifeTime;
  }


  /**
   * Check whether the object has expired.
   *
   * @return True if it has expired, else false.
   */
  protected boolean expired() {
    if (this.livesForever) {
      return false;
    }

    final Date currentTime = Calendar.getInstance().getTime();

    return this.expiryTime.before(currentTime);
  }


  /**
   * Updater thread used to update the string at the specified interval.
   */
  private class StringUpdater extends Thread {
    /**
     * The invoking (SecureString) object.
     */
    private SecureString parent = null;

    /**
     * Whether or not the Thread is active.
     */
    private boolean      active = true;


    /**
     * Run the updater thread.
     */
    public void run() {
      while (true) {
        if (this.parent.debug) {
          System.out.println("Testing   : " + new Date() + " " + this.parent.expired());
        }

        synchronized (this) {
          if (string != null) {
            final int l = string.length;
            if ((l > 0) && this.parent.expired()) {
              synchronized (this.parent) {
                this.parent.destroy();
              }
            }
          }

          try {
            Thread.sleep(this.parent.updateInterval);

            if (!active) {
              break;
            }
          } catch (InterruptedException ie) {}
        }
      }
    }


    /**
     * Activate or deactivate the updater thread.
     *
     * @param b True to activate the thread, false to deactivate the thread.
     */
    protected synchronized void setActive(boolean b) {
      active = b;
    }


    /**
     * Set the invoker of this thread. This is used to synchronize the thread
     * with its invoking object.
     *
     * @param parent The parent (Cache) object.
     */
    protected synchronized void setParent(SecureString parent) {
      this.parent = parent;
    }
  }
}
