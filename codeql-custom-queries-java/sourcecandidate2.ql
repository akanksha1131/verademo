/**
 * Enhanced query to detect sources of user-controlled input
 * @name source-detect-final
 * @kind problem
 * @problem.severity warning
 * @id java/example/source-detection
 */

 import java
 import semmle.code.java.dataflow.DataFlow
 
 // Define sources of user-controlled input, tailored to specific taint sources
 predicate isSource(DataFlow::Node src) {
   // Detect parameters explicitly named as sources
   exists(Parameter p |
    p.getName() in [
        "username", "password", "remember", "target", "realName",
        "blabName", "blabberUsername", "command", "cpassword",
        "host", "fortuneFile", "count", "length", "imageName"
    ] and
    src.asParameter() = p    
   )
   // Detect HttpServletRequest methods like getParameter, getHeader, etc.
   or
   exists(MethodAccess access |
     access.getMethod().getDeclaringType().getName() = "javax.servlet.http.HttpServletRequest" and
     access.getMethod().hasName(["getParameter", "getHeader", "getCookies"]) and
     src.asExpr() = access
   )
   // Detect calls to specified taint-related methods
   or
   exists(MethodAccess methodAccess |
     methodAccess.getMethod().getDeclaringType().getName() = "YourAppNamespace" and
     methodAccess.getMethod().getName() in [
       "processLogin", "processRegister", "processRegisterFinish", 
       "processBlabbers", "downloadProfileImage", "updateProfile", 
       "createFromRequest", "registerUser", "ping", "getMoreFeed"
     ] and
     src.asExpr() = methodAccess
   )
   // Detect user input from IO streams like BufferedReader or Scanner
   or
   exists(MethodAccess readAccess |
     readAccess.getMethod().getDeclaringType().getName() in ["java.io.BufferedReader", "java.util.Scanner"] and
     readAccess.getMethod().getName() in ["readLine", "nextLine"] and
     src.asExpr() = readAccess
   )
   // Exclude trusted libraries to avoid false positives
   and not exists(MethodAccess libMethod |
     libMethod.getMethod().getDeclaringType().getName().matches("java.*") or
     libMethod.getMethod().getDeclaringType().getName().matches("org.springframework.*") and
     src.asExpr() = libMethod
   )
 }
 
 // Query to output each detected source with detailed information
 from DataFlow::Node source
 where isSource(source)
 select 
   source, 
   "Source element detected in package: " + source.getEnclosingCallable().getDeclaringType().getPackage().getName() + 
   ", class: " + source.getEnclosingCallable().getDeclaringType().getName() +
   ", function: " + source.getEnclosingCallable().getName() +
   ", signature: " + source.getEnclosingCallable().getQualifiedName() + 
   "(" + source.getEnclosingCallable().getSignature() + ")"
 