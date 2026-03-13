/**
 * Keychain Access Monitor
 *
 * Hooks SecItemCopyMatching and SecItemAdd to log keychain operations
 * during dynamic analysis. Captures item classes, access groups, and
 * account names without extracting sensitive values.
 *
 * Usage:
 *   frida -U -f <bundle_id> -l keychain_dump.js --no-pause
 *
 * WARNING: For authorized security testing only.
 */

"use strict";

var kSecClass = {
  "agrp": "kSecAttrAccessGroup",
  "acct": "kSecAttrAccount",
  "svce": "kSecAttrService",
  "class": "kSecClass",
  "labl": "kSecAttrLabel",
};

var kSecClassValues = {
  "genp": "kSecClassGenericPassword",
  "inet": "kSecClassInternetPassword",
  "cert": "kSecClassCertificate",
  "keys": "kSecClassKey",
  "idnt": "kSecClassIdentity",
};

function describeQuery(query) {
  if (!query || query.isNull()) return "{}";

  var dict = ObjC.Object(query);
  var result = {};

  try {
    var keys = dict.allKeys();
    for (var i = 0; i < keys.count(); i++) {
      var key = keys.objectAtIndex_(i).toString();
      var val = dict.objectForKey_(keys.objectAtIndex_(i));

      var label = kSecClass[key] || key;
      var value = val.toString();
      result[label] = kSecClassValues[value] || value;
    }
  } catch (e) {
    result["_error"] = e.message;
  }

  return JSON.stringify(result, null, 2);
}

if (ObjC.available) {
  // Hook SecItemCopyMatching — reads from keychain
  try {
    Interceptor.attach(
      Module.findExportByName("Security", "SecItemCopyMatching"),
      {
        onEnter: function (args) {
          this.query = args[0];
          console.log("\n[KEYCHAIN READ] SecItemCopyMatching");
          console.log("  Query: " + describeQuery(this.query));
        },
        onLeave: function (retval) {
          var status = retval.toInt32();
          console.log(
            "  Result: " + (status === 0 ? "found" : "errSec " + status)
          );
        },
      }
    );
    console.log("[+] Hooked SecItemCopyMatching");
  } catch (e) {
    console.log("[-] SecItemCopyMatching hook failed: " + e.message);
  }

  // Hook SecItemAdd — writes to keychain
  try {
    Interceptor.attach(
      Module.findExportByName("Security", "SecItemAdd"),
      {
        onEnter: function (args) {
          this.attrs = args[0];
          console.log("\n[KEYCHAIN WRITE] SecItemAdd");
          console.log("  Attributes: " + describeQuery(this.attrs));
        },
        onLeave: function (retval) {
          var status = retval.toInt32();
          console.log(
            "  Result: " + (status === 0 ? "success" : "errSec " + status)
          );
        },
      }
    );
    console.log("[+] Hooked SecItemAdd");
  } catch (e) {
    console.log("[-] SecItemAdd hook failed: " + e.message);
  }

  // Hook SecItemUpdate — modifies keychain items
  try {
    Interceptor.attach(
      Module.findExportByName("Security", "SecItemUpdate"),
      {
        onEnter: function (args) {
          console.log("\n[KEYCHAIN UPDATE] SecItemUpdate");
          console.log("  Query: " + describeQuery(args[0]));
        },
        onLeave: function (retval) {
          var status = retval.toInt32();
          console.log(
            "  Result: " + (status === 0 ? "success" : "errSec " + status)
          );
        },
      }
    );
    console.log("[+] Hooked SecItemUpdate");
  } catch (e) {
    console.log("[-] SecItemUpdate hook failed: " + e.message);
  }

  // Hook SecItemDelete — removes keychain items
  try {
    Interceptor.attach(
      Module.findExportByName("Security", "SecItemDelete"),
      {
        onEnter: function (args) {
          console.log("\n[KEYCHAIN DELETE] SecItemDelete");
          console.log("  Query: " + describeQuery(args[0]));
        },
        onLeave: function (retval) {
          var status = retval.toInt32();
          console.log(
            "  Result: " + (status === 0 ? "success" : "errSec " + status)
          );
        },
      }
    );
    console.log("[+] Hooked SecItemDelete");
  } catch (e) {
    console.log("[-] SecItemDelete hook failed: " + e.message);
  }

  console.log("[+] Keychain monitor loaded — watching all SecItem operations");
} else {
  console.log("[-] Objective-C runtime not available");
}
