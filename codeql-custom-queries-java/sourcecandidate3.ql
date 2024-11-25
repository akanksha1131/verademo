/**
 * Enhanced query to detect sources of user-controlled input
 * @name source-detect-1
 * @kind problem
 * @problem.severity warning
 * @id java/example/source-detection
 */

 import java
 import semmle.code.java.dataflow.DataFlow
 
 // Define sources of user-controlled input, tailored to specific taint sources
 predicate isSource(DataFlow::Node src, string sourceType, string sourceName, string sourceDataType) {
   // Parameters commonly associated with CWEs
   exists(Parameter p |
     p.getName() in [
       "username", "password", "remember", "target", "realName",
       "blabName", "blabberUsername", "command", "cpassword",
       "host", "fortuneFile", "count", "length", "imageName"
     ] and
     src.asParameter() = p and
     sourceType = "Parameter" and
     sourceName = p.getName() and
     sourceDataType = p.getType().toString()
   ) or
   // Method calls for cookies and session IDs
   exists(MethodAccess access |
     access.getMethod().getDeclaringType().getName() = "javax.servlet.http.HttpServletRequest" and
     (
       access.getMethod().hasName(["getCookies", "getSession", "getId"]) or
       access.getMethod().hasName("getCookieFromRequestByName")
     ) and
     src.asExpr() = access and
     sourceType = "MethodAccess" and
     sourceName = access.getMethod().getName() and
     sourceDataType = access.getType().toString()
   )
 }
 
 // Query to output each detected source with detailed information
 from DataFlow::Node source, string sourceType, string sourceName, string sourceDataType
 where isSource(source, sourceType, sourceName, sourceDataType)
 select 
   source, 
   "Source element detected in package: " + 
   source.getEnclosingCallable().getDeclaringType().getPackage().getName() + 
   ", class: " + source.getEnclosingCallable().getDeclaringType().getName() +
   ", function: " + source.getEnclosingCallable().getName() +
   ", signature: " + source.getEnclosingCallable().getQualifiedName() + 
   "(" + source.getEnclosingCallable().getSignature() + ")" +
   ". Source type: " + sourceType +
   ", Source name: " + sourceName +
   ", Source data type: " + sourceDataType
 