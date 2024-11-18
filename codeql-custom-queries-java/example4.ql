/**
 * This is an automatically generated file
 * @name source-candidate-detection
 * @kind problem
 * @problem.severity warning
 * @id java/example/source-detection
 */

 import java
 import semmle.code.java.dataflow.DataFlow
 
 // Predicate to define sources of user-controlled input in the application.
 predicate isSource(DataFlow::Node src) {
   // Check if the source is a method parameter with specific sensitive names.
   exists(Parameter p |
     // List of parameter names commonly associated with user-controlled input.
     p.getName() in ["realName", "blabName", "username", "file", "command", "blabberUsername", "password", "remember", "target"] and
     // Match the parameter to the current data flow node.
     src.asParameter() = p
   )
   or
   // Check for method accesses to `HttpServletRequest` methods that return user input.
   exists(MethodAccess access |
     // Ensure the method belongs to `javax.servlet.http.HttpServletRequest`.
     access.getMethod().getDeclaringType().getName() = "javax.servlet.http.HttpServletRequest" and
     (
       // Identify commonly used methods to retrieve user-controlled data.
       access.getMethod().hasName("getParameter") or
       access.getMethod().hasName("getHeader") or
       access.getMethod().hasName("getCookies")
     ) and
     // Confirms that the node represents data passed to or returned from method
     src.asExpr() = access
   )
   or
   // Check for reflective method calls that could lead to dynamic behavior.
   exists(MethodAccess cmdClassAccess |
     // Identify methods known to invoke classes or objects dynamically.
     cmdClassAccess.getMethod().getName() in ["forName", "newInstance"] and
     // Match the method access to the current data flow node.
     src.asExpr() = cmdClassAccess
   )
   or
   // Check for application-specific methods explicitly processing sensitive information.
   exists(MethodAccess methodAccess |
     // Methods commonly associated with handling login or registration inputs.
     methodAccess.getMethod().getName() in ["processLogin", "showPasswordHint", "processRegister"] and
     // Match the method access to the current data flow node.
     src.asExpr() = methodAccess
   )
   // Exclude library methods from the source detection to reduce noise.
   and not exists(MethodAccess libMethod |
     // Exclude methods from standard Java and Spring libraries.
     libMethod.getMethod().getDeclaringType().getName().matches("java.*") or
     libMethod.getMethod().getDeclaringType().getName().matches("org.springframework.*") and
     // Ensure the excluded method is part of the current data flow node.
     src.asExpr() = libMethod
   )
 }
 
 // Query to detect and report source elements.
 from DataFlow::Node source
 // Apply the `isSource` predicate to filter user-controlled input sources.
 where isSource(source)
 select 
   source, 
   // Provide details of the source: package, class, and function.
   "Source element in package: " + source.getEnclosingCallable().getDeclaringType().getPackage().getName() + 
   ", class: " + source.getEnclosingCallable().getDeclaringType().getName() +
   ", function: " + source.getEnclosingCallable().getName()
 