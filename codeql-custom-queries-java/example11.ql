/**
 * @kind path-problem
 * @name Path Between Sources and Sinks
 * @id java/example/path-detection
 * @description Tracks paths between sources and sinks where unvalidated data may lead to vulnerabilities.
 */

 import java
 import semmle.code.java.dataflow.DataFlow
 
 /**
  * Define sources of user-controlled input.
  */
 predicate isSource(DataFlow::Node src) {
    // Parameters commonly associated with CWEs
    exists(Parameter p |
      p.getName() in [
        "username", "password", "remember", "target", "realName",
        "blabName", "blabberUsername", "command", "cpassword",
        "host", "fortuneFile", "count", "length", "imageName"
      ] 
    ) or
    // Method calls for cookies and session IDs
    exists(MethodAccess access |
      access.getMethod().getDeclaringType().getName() = "javax.servlet.http.HttpServletRequest" and
      (
        access.getMethod().hasName(["getCookies", "getSession", "getId"]) or
        access.getMethod().hasName("getCookieFromRequestByName")
      ) and
      src.asExpr() = access 
    )
  }
 
 /**
  * Define sinks where unvalidated data could lead to vulnerabilities.
  */
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
 
 /**
  * Main query to detect and visualize paths from sources to sinks.
  */
 from DataFlow::PathNode source, DataFlow::PathNode sink
 where isSource(source.getNode()) and isSink(sink.getNode()) 
 select
   sink, source, sink,
   "Data flows from source to sink:\nSource: " +
   source.getNode().getEnclosingCallable().getQualifiedName() +
   "\nSink: " + sink.getNode().getEnclosingCallable().getQualifiedName()
 