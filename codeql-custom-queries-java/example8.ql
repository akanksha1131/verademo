/**
 * Enhanced query to detect sinks where unvalidated data could lead to vulnerabilities
 * @name sink-detect
 * @kind problem
 * @problem.severity warning
 * @id java/example/sink-detection
 */

 import java
 import semmle.code.java.dataflow.DataFlow
 
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
     cmdExec.getMethod().getDeclaringType().getName() = "java.lang.Runtime" and
     cmdExec.getMethod().hasName("exec") or
     cmdExec.getMethod().getDeclaringType().getName() = "java.lang.ProcessBuilder" and
     cmdExec.getMethod().hasName("start") and
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
   or
   exists(MethodAccess jspServiceAccess |
     jspServiceAccess.getMethod().getDeclaringType().getName().matches(".*\\.jsp") and
     jspServiceAccess.getMethod().hasName("_jspService") and
     snk.asExpr() = jspServiceAccess
   )
   or
   exists(MethodAccess jspParameter |
     jspParameter.getMethod().getDeclaringType().getName() = "javax.servlet.jsp.JspWriter" and
     jspParameter.getMethod().hasName("write") and
     snk.asExpr() = jspParameter
   )
   and not exists(MethodAccess libMethod |
     libMethod.getMethod().getDeclaringType().getName().matches("java.*") or
     libMethod.getMethod().getDeclaringType().getName().matches("org.springframework.*") and
     snk.asExpr() = libMethod
   )
 }
 
 // Query to output each detected sink with its package, class, function declaration, and signature
 from DataFlow::Node sink
 where isSink(sink)
 select 
   sink, 
   "Sink element in package: " + sink.getEnclosingCallable().getDeclaringType().getPackage().getName() + 
   ", class: " + sink.getEnclosingCallable().getDeclaringType().getName() +
   ", function: " + sink.getEnclosingCallable().getName() +
   ", signature: " + sink.getEnclosingCallable().getQualifiedName() + 
   "(" + sink.getEnclosingCallable().getSignature() + ")"
 