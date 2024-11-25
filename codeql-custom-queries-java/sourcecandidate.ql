/**
 * Enhanced query to detect sources of user-controlled input
 * @name source-detect
 * @kind problem
 * @problem.severity warning
 * @id java/example/source-detection
 */

 import java
 import semmle.code.java.dataflow.DataFlow
 
 // Define sources of user-controlled input, tailored to specific taint sources
 predicate isSource(DataFlow::Node src) {
   exists(Parameter p |
     p.getName() in ["username", "password", "remember", "target", "realName", 
                     "blabName", "blabberUsername", "command", "cpassword", 
                     "host", "fortuneFile", "count", "length"] and
     src.asParameter() = p
   )
   or
   exists(MethodAccess access |
     access.getMethod().getDeclaringType().getName() = "javax.servlet.http.HttpServletRequest" and
     (
       access.getMethod().hasName("getParameter") or
       access.getMethod().hasName("getHeader") or
       access.getMethod().hasName("getCookies")
     ) and
     src.asExpr() = access
   )
   or
   exists(MethodAccess methodAccess |
     methodAccess.getMethod().getName() in [
       "processLogin", "processRegister", "processRegisterFinish", 
       "processBlabbers", "downloadProfileImage", "updateProfile", 
       "createFromRequest", "registerUser", "ping", "fortune", "getMoreFeed"
     ] and
     src.asExpr() = methodAccess
   )
   or
   exists(MethodAccess readAccess |
     readAccess.getMethod().getDeclaringType().getName() in ["java.io.BufferedReader", "java.util.Scanner"] and
     readAccess.getMethod().getName() in ["readLine", "nextLine"] and
     src.asExpr() = readAccess
   )
   and not exists(MethodAccess libMethod |
     libMethod.getMethod().getDeclaringType().getName().matches("java.*") or
     libMethod.getMethod().getDeclaringType().getName().matches("org.springframework.*") and
     src.asExpr() = libMethod
   )
 }
 
 // Query to output each detected source with its package, class, function declaration, and signature
 from DataFlow::Node source
 where isSource(source)
 select 
   source, 
   "Source element in package: " + source.getEnclosingCallable().getDeclaringType().getPackage().getName() + 
   ", class: " + source.getEnclosingCallable().getDeclaringType().getName() +
   ", function: " + source.getEnclosingCallable().getName() +
   ", signature: " + source.getEnclosingCallable().getQualifiedName() + 
   "(" + source.getEnclosingCallable().getSignature() + ")"
 