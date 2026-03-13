/**
 * SSL Pinning Bypass for iOS
 *
 * Hooks common SSL pinning implementations to allow traffic interception
 * during dynamic security testing.
 *
 * Usage:
 *   frida -U -f <bundle_id> -l ssl_pinning_bypass.js --no-pause
 *
 * Targets:
 *   - NSURLSession certificate validation
 *   - SecTrustEvaluate / SecTrustEvaluateWithError
 *   - Custom URLSession delegate methods
 *
 * WARNING: For authorized security testing only.
 */

"use strict";

if (ObjC.available) {
  // Bypass SecTrustEvaluateWithError (iOS 12+)
  try {
    const SecTrustEvaluateWithError = new NativeFunction(
      Module.findExportByName("Security", "SecTrustEvaluateWithError"),
      "bool",
      ["pointer", "pointer"]
    );

    Interceptor.replace(
      Module.findExportByName("Security", "SecTrustEvaluateWithError"),
      new NativeCallback(
        function (trust, error) {
          console.log("[*] SecTrustEvaluateWithError bypassed");
          return 1; // true = trusted
        },
        "bool",
        ["pointer", "pointer"]
      )
    );
    console.log("[+] Hooked SecTrustEvaluateWithError");
  } catch (e) {
    console.log("[-] SecTrustEvaluateWithError not found: " + e.message);
  }

  // Bypass SecTrustEvaluate (legacy)
  try {
    Interceptor.replace(
      Module.findExportByName("Security", "SecTrustEvaluate"),
      new NativeCallback(
        function (trust, result) {
          Memory.writeU32(result, 4); // kSecTrustResultUnspecified (trusted)
          console.log("[*] SecTrustEvaluate bypassed");
          return 0; // errSecSuccess
        },
        "int",
        ["pointer", "pointer"]
      )
    );
    console.log("[+] Hooked SecTrustEvaluate");
  } catch (e) {
    console.log("[-] SecTrustEvaluate not found: " + e.message);
  }

  // Bypass NSURLSessionDelegate certificate challenges
  try {
    const resolver = ObjC.classes.NSURLSession[
      "- URLSession:didReceiveChallenge:completionHandler:"
    ];
    if (resolver) {
      Interceptor.attach(resolver.implementation, {
        onEnter: function (args) {
          console.log("[*] URLSession challenge intercepted");
        },
      });
    }
    console.log("[+] Monitoring NSURLSession challenges");
  } catch (e) {
    console.log("[-] NSURLSession hook skipped: " + e.message);
  }

  console.log("[+] SSL pinning bypass loaded");
} else {
  console.log("[-] Objective-C runtime not available");
}
