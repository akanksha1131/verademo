/**
 * Query to detect various security sinks where unvalidated data could lead to vulnerabilities
 *
 * @name sink-detection-all
 * @kind problem
 * @problem.severity high
 * @id java/example/sink-detection-all
 */

 import java
 import semmle.code.java.dataflow.DataFlow
 
 predicate isSink(DataFlow::Node snk) {
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
     cmdExec.getMethod().hasName("exec") and
     snk.asExpr() = cmdExec
   )
   or
   exists(MethodAccess cmdExec2 |
     cmdExec2.getMethod().getDeclaringType().getName() = "java.lang.ProcessBuilder" and
     cmdExec2.getMethod().hasName("start") and
     snk.asExpr() = cmdExec2
   )
   or
   // Detect unsafe reflection sinks
   exists(MethodAccess classForName |
     classForName.getMethod().getDeclaringType().getName() = "java.lang.Class" and
     classForName.getMethod().hasName("forName") and
     snk.asExpr() = classForName
   )
   or
   // Detect object deserialization sinks
   exists(MethodAccess objectStreamAccess |
     objectStreamAccess.getMethod().getDeclaringType().getName() = "java.io.ObjectInputStream" and
     objectStreamAccess.getMethod().hasName("readObject") and
     snk.asExpr() = objectStreamAccess
   )
   or
   // Detect email injection sinks (subject)
   exists(MethodAccess emailSubject |
     emailSubject.getMethod().getDeclaringType().getName() = "javax.mail.Message" and
     emailSubject.getMethod().hasName("setSubject") and
     snk.asExpr() = emailSubject
   )
   or
   // Detect logging sensitive data sinks
   exists(MethodAccess loggerMethod |
     loggerMethod.getMethod().getDeclaringType().getName().matches(".*Logger.*") and
     loggerMethod.getMethod().hasName("info") and
     snk.asExpr() = loggerMethod
   )
   or
   // Detect file access sinks (file transfer)
   exists(MethodAccess fileTransfer |
     fileTransfer.getMethod().getDeclaringType().getName() = "java.io.File" and
     fileTransfer.getMethod().hasName("transferTo") and
     snk.asExpr() = fileTransfer
   )
   or
   // Detect file operations with user input
   exists(MethodAccess fileAccess |
     fileAccess.getMethod().getDeclaringType().getName() = "java.io.FileInputStream" and
     fileAccess.getMethod().hasName("FileInputStream") and
     snk.asExpr() = fileAccess
   )
   or
   // Detect file path access sinks
   exists(MethodAccess filePathAccess |
     filePathAccess.getMethod().getDeclaringType().getName() = "java.nio.file.Files" and
     (
       filePathAccess.getMethod().hasName("write") or
       filePathAccess.getMethod().hasName("copy")
     ) and
     snk.asExpr() = filePathAccess
   )
   or
   // Detect path concatenation sinks
   exists(BinaryExpr pathConcat |
     pathConcat.getLeftOperand() instanceof Literal and
     snk.asExpr() = pathConcat
   )
   or
   // Detect file input stream sinks
   exists(MethodAccess fileIO |
     fileIO.getMethod().getDeclaringType().getName() = "java.io.FileInputStream" and
     fileIO.getMethod().hasName("FileInputStream") and
     snk.asExpr() = fileIO
   )
   or
   // Detect reflection (unsafe class loading) through user-controlled input
   exists(MethodAccess classLoad |
     classLoad.getMethod().getDeclaringType().getName() = "java.lang.Class" and
     classLoad.getMethod().hasName("forName") and
     snk.asExpr() = classLoad
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
 