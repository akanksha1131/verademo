/**
 * This is an automatically generated file
 * @name source-candidate-detection
 * @kind problem
 * @problem.severity warning
 * @id java/example/source-detection
 */

 import java
 import semmle.code.java.dataflow.DataFlow
 
 // Define sources of user-controlled input, excluding Java and Spring library functions
 predicate isSource(DataFlow::Node src) {
   exists(Parameter p |
     p.getName() in ["realName", "blabName", "username", "file", "command", "blabberUsername", "password", "remember", "target"] and
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
   exists(MethodAccess cmdClassAccess |
     cmdClassAccess.getMethod().getName() in ["forName", "newInstance"] and
     src.asExpr() = cmdClassAccess
   )
   or
   exists(MethodAccess methodAccess |
     methodAccess.getMethod().getName() in ["processLogin", "showPasswordHint", "processRegister"] and
     src.asExpr() = methodAccess
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
  ", function: " + source.getEnclosingCallable().getName() 
 

