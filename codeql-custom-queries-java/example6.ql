/**
 * This is an automatically generated file
 * @name v6
 * @kind problem
 * @problem.severity warning
 * @id java/example/hello-world
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
   // Exclude Java and Spring library methods
   and not exists(MethodAccess libMethod |
     libMethod.getMethod().getDeclaringType().getName().matches("java.*") or
     libMethod.getMethod().getDeclaringType().getName().matches("org.springframework.*") and
     src.asExpr() = libMethod
   )
 }

 // Define sinks where unvalidated data could lead to vulnerabilities, excluding Java and Spring library functions
 predicate isSink(DataFlow::Node snk) {
   exists(MethodAccess fileAccess |
     fileAccess.getMethod().getDeclaringType().getName() = "java.io.File" and
     (
       fileAccess.getMethod().hasName("renameTo") or
       fileAccess.getMethod().hasName("new File")
     ) and
     snk.asExpr() = fileAccess
   )
   or
   exists(MethodAccess sqlMethod |
     sqlMethod.getMethod().getDeclaringType().getName() = "java.sql.Statement" and
     (
       sqlMethod.getMethod().hasName("executeQuery") or
       sqlMethod.getMethod().hasName("executeUpdate") or
       sqlMethod.getMethod().hasName("execute")
     ) and
     snk.asExpr() = sqlMethod
   )
   or
   exists(BinaryExpr concatExpr |
     (concatExpr.getLeftOperand() instanceof Literal or concatExpr.getRightOperand() instanceof Literal) and
     snk.asExpr() = concatExpr
   )
   or
   exists(MethodAccess cmdExec |
     cmdExec.getMethod().getName() in ["exec", "start"] and
     snk.asExpr() = cmdExec
   )
   or
   exists(MethodAccess objectStreamAccess |
     objectStreamAccess.getMethod().getDeclaringType().getName() = "java.io.ObjectInputStream" and
     objectStreamAccess.getMethod().hasName("readObject") and
     snk.asExpr() = objectStreamAccess
   )
   or
   exists(MethodAccess formatAccess |
     formatAccess.getMethod().getName() = "format" and
     snk.asExpr() = formatAccess
   )
   // Exclude Java and Spring library methods
   and not exists(MethodAccess libMethod |
     libMethod.getMethod().getDeclaringType().getName().matches("java.*") or
     libMethod.getMethod().getDeclaringType().getName().matches("org.springframework.*") and
     snk.asExpr() = libMethod
   )
 }

 // Main query to output the details of each detected source and sink pair
 from DataFlow::Node source, DataFlow::Node sink
 where isSource(source) and isSink(sink)
 select 
   source, 
   source.getEnclosingCallable().getSignature() + " : " + source.getEnclosingCallable().getBody().toString() + " is source; " + 
   sink.getEnclosingCallable().getSignature() + " : " + sink.getEnclosingCallable().getBody().toString() + " is sink;"
