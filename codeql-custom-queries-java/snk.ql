/**
 * @name snk
 * @kind problem
 * @problem.severity warnings
 * @id java/example/sink-detection-all
 */

 import java
 import semmle.code.java.dataflow.DataFlow
 
 predicate isSink(DataFlow::Node snk) {
   // Detect Logger sinks
   exists(MethodAccess loggerMethod |
     loggerMethod.getMethod().getDeclaringType().getName().matches(".*Logger.*") and
     loggerMethod.getMethod().hasName("info") and
     snk.asExpr() = loggerMethod.getArgument(0)
   )
   or
   // Detect SQL execution sinks (Statement.execute methods)
   exists(MethodAccess sqlMethod |
     sqlMethod.getMethod().getDeclaringType().getName() = "java.sql.Statement" and
     (
       sqlMethod.getMethod().hasName("executeQuery") or
       sqlMethod.getMethod().hasName("executeUpdate") or
       sqlMethod.getMethod().hasName("execute")
     ) and
     snk.asExpr() = sqlMethod.getArgument(0)
   )
   or
   // Detect PreparedStatement setString sinks
   exists(MethodAccess prepStatementMethod |
     prepStatementMethod.getMethod().getDeclaringType().getName() = "java.sql.PreparedStatement" and
     prepStatementMethod.getMethod().hasName("setString") and
     snk.asExpr() = prepStatementMethod.getArgument(1)
   )
   or
   // Detect Class.forName method sinks
   exists(MethodAccess classForName |
     classForName.getMethod().getDeclaringType().getName() = "java.lang.Class" and
     classForName.getMethod().hasName("forName") and
     snk.asExpr() = classForName.getArgument(0)
   )
   or
   // Detect Runtime.exec command execution sinks
   exists(MethodAccess runtimeExec |
     runtimeExec.getMethod().getDeclaringType().getName() = "java.lang.Runtime" and
     runtimeExec.getMethod().hasName("exec") and
     snk.asExpr() = runtimeExec.getArgument(0)
   )
   or
   // Detect ProcessBuilder start command execution sinks
   exists(MethodAccess processBuilderStart |
     processBuilderStart.getMethod().getDeclaringType().getName() = "java.lang.ProcessBuilder" and
     processBuilderStart.getMethod().hasName("start") and
     snk.asExpr() = processBuilderStart.getArgument(0)
   )
   or
   // Detect MessageDigest getInstance method sinks
   exists(MethodAccess messageDigestMethod |
     messageDigestMethod.getMethod().getDeclaringType().getName() = "java.security.MessageDigest" and
     messageDigestMethod.getMethod().hasName("getInstance") and
     snk.asExpr() = messageDigestMethod.getArgument(0)
   )
   or
   // Detect ObjectInputStream readObject method sinks
   exists(MethodAccess objectStreamAccess |
     objectStreamAccess.getMethod().getDeclaringType().getName() = "java.io.ObjectInputStream" and
     objectStreamAccess.getMethod().hasName("readObject") and
     snk.asExpr() = objectStreamAccess.getArgument(0)
   )
   or
   // Detect setUsernameCookie sinks
   exists(MethodAccess sessionUtils |
     sessionUtils.getMethod().getDeclaringType().getName() = "Utils" and
     sessionUtils.getMethod().hasName("setUsernameCookie") and
     snk.asExpr() = sessionUtils.getArgument(0)
   )
   or
   // Detect String.format method sinks
   exists(MethodAccess formatMethod |
     formatMethod.getMethod().hasName("format") and
     snk.asExpr() = formatMethod.getArgument(0)
   )
   or
   // Detect file input stream sinks
   exists(MethodAccess fileIO |
     fileIO.getMethod().getDeclaringType().getName() = "java.io.FileInputStream" and
     fileIO.getMethod().hasName("FileInputStream") and
     snk.asExpr() = fileIO.getArgument(0)
   )
   or
   // Detect file transfer sinks
   exists(MethodAccess fileTransfer |
     fileTransfer.getMethod().getDeclaringType().getName() = "java.io.File" and
     fileTransfer.getMethod().hasName("transferTo") and
     snk.asExpr() = fileTransfer.getArgument(0)
   )
 }
 
 // Query to output each detected sink with its package, class, function declaration, and signature
 from DataFlow::Node sink
 where isSink(sink)
 select sink,
   "Sink element in type: " + sink.getEnclosingCallable().getDeclaringType().getName() + ", method: "
     + sink.getEnclosingCallable().getName() + ", signature: " +
     sink.getEnclosingCallable().getQualifiedName() + "(" +
     sink.getEnclosingCallable().getSignature() + ")" + ", sink data type: " +
     sink.getType().getName()
 