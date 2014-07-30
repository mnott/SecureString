package com.sap.securestring;

public class SecureString {
  private char[] str;
  
  public SecureString() {}
  
  public SecureString(String str) {
    this.str = str.toCharArray();
  }

}
