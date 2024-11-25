/**
 * Enhanced query to detect sinks where unvalidated data could lead to vulnerabilities
 * @name sink-detect-3
 * @kind problem
 * @problem.severity warning
 * @id java/example/sink-detection
 */

 import java
 import semmle.code.java.dataflow.DataFlow
 
 // Define sinks where unvalidated data could lead to vulnerabilities
 predicate isSink(DataFlow::Node snk) {
   // Detect file access sinks
   exists(MethodAccess fileAccess |
     fileAccess.getMethod().getDeclaringType().getName() = "java.io.File" and
     fileAccess.getMethod().hasName("transferTo") and
     snk.asExpr() = fileAccess
   )
   or
   // Detect SQL injection sinks
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
   // Detect command execution sinks
   exists(MethodAccess cmdExec |
     cmdExec.getMethod().getDeclaringType().getName() = "java.lang.Runtime" and
     cmdExec.getMethod().hasName("exec") or
     cmdExec.getMethod().getDeclaringType().getName() = "java.lang.ProcessBuilder" and
     cmdExec.getMethod().hasName("start") and
     snk.asExpr() = cmdExec
   )
   or
   // Detect object stream access sinks
   exists(MethodAccess objectStreamAccess |
     objectStreamAccess.getMethod().getDeclaringType().getName() = "java.io.ObjectInputStream" and
     objectStreamAccess.getMethod().hasName("readObject") and
     snk.asExpr() = objectStreamAccess
   )
   or
   // Detect string concatenation sinks
   exists(BinaryExpr concatExpr |
     (concatExpr.getLeftOperand() instanceof Literal or concatExpr.getRightOperand() instanceof Literal) and
     snk.asExpr() = concatExpr
   )
   or
   // Detect format method sinks
   exists(MethodAccess formatAccess |
     formatAccess.getMethod().hasName("format") and
     snk.asExpr() = formatAccess
   )
   or
   // Detect session management sinks
   exists(MethodAccess sessionUtils |
     sessionUtils.getMethod().getDeclaringType().getName() = "Utils" and
     (
       sessionUtils.getMethod().hasName("setSessionUserName") or
       sessionUtils.getMethod().hasName("setUsernameCookie")
     ) and
     snk.asExpr() = sessionUtils
   )
   or
   // Detect MessageDigest method sinks
   exists(MethodAccess digestMethod |
     digestMethod.getMethod().getDeclaringType().getName() = "java.security.MessageDigest" and
     digestMethod.getMethod().hasName("getInstance") and
     snk.asExpr() = digestMethod
   )
   or
   // Detect Class.forName method sinks
   exists(MethodAccess classForName |
     classForName.getMethod().getDeclaringType().getName() = "java.lang.Class" and
     classForName.getMethod().hasName("forName") and
     snk.asExpr() = classForName
   )
   or
   // Detect Logger method sinks
   exists(MethodAccess loggerMethod |
     loggerMethod.getMethod().getDeclaringType().getName().matches(".*Logger.*") and
     loggerMethod.getMethod().hasName("info") and
     snk.asExpr() = loggerMethod
   )
   or
   // Detect file input stream sinks
   exists(MethodAccess fileIO |
     fileIO.getMethod().getDeclaringType().getName() = "java.io.FileInputStream" and
     fileIO.getMethod().hasName("FileInputStream") and
     snk.asExpr() = fileIO
   )
   or
   // Detect path concatenation sinks
   exists(BinaryExpr pathConcat |
     pathConcat.getLeftOperand() instanceof Literal and
     snk.asExpr() = pathConcat
   )
 }
 
 // Query to output each detected sink with its package, class, function declaration, and signature
 from DataFlow::Node sink
 where isSink(sink)
 select 
  sink, 
  "Sink element in type: " + sink.getEnclosingCallable().getDeclaringType().getName() + 
  ", method: " + sink.getEnclosingCallable().getName() +
  ", signature: " + sink.getEnclosingCallable().getQualifiedName() + 
  "(" + sink.getEnclosingCallable().getSignature() + ")" +
  ", sink data type: " + sink.getType().getName()
