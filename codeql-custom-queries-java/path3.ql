/**
 * ...
 *
 * @kind path-problem
 * @name Path3
 * @id java/example/path-detection
 * ...
 */

import semmle.code.java.dataflow.DataFlow

module MyFlowConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    // Parameters commonly associated with CWEs
    exists(Parameter p |
      p.getName() in [
          "username", "password", "remember", "target", "realName", "blabName", "blabberUsername",
          "command", "cpassword", "host", "fortuneFile", "count", "length", "imageName"
        ]
    )
    or
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
      snk.asExpr() = fileAccess.getAnArgument() // Select arguments
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
      snk.asExpr() = sqlMethod.getAnArgument() // Select arguments
    )
    or
    // Detect command execution sinks
    exists(MethodAccess cmdExec |
      cmdExec.getMethod().getDeclaringType().getName() = "java.lang.Runtime" and
      cmdExec.getMethod().hasName("exec")
      or
      (
        cmdExec.getMethod().getDeclaringType().getName() = "java.lang.ProcessBuilder" and
        cmdExec.getMethod().hasName("start")
      ) and
      snk.asExpr() = cmdExec.getAnArgument() // Select arguments
    )
    or
    // Detect object stream access sinks
    exists(MethodAccess objectStreamAccess |
      objectStreamAccess.getMethod().getDeclaringType().getName() = "java.io.ObjectInputStream" and
      objectStreamAccess.getMethod().hasName("readObject") and
      snk.asExpr() = objectStreamAccess.getAnArgument() // Select arguments
    )
    or
    // Detect format method sinks
    exists(MethodAccess formatAccess |
      formatAccess.getMethod().hasName("format") and
      snk.asExpr() = formatAccess.getAnArgument() // Select arguments
    )
    or
    // Detect session management sinks
    exists(MethodAccess sessionUtils |
      sessionUtils.getMethod().getDeclaringType().getName() = "Utils" and
      (
        sessionUtils.getMethod().hasName("setSessionUserName") or
        sessionUtils.getMethod().hasName("setUsernameCookie")
      ) and
      snk.asExpr() = sessionUtils.getArgument(1) // Select arguments
    )
    or
    // Detect Logger method sinks
    exists(MethodAccess loggerMethod |
      loggerMethod.getMethod().getDeclaringType().getName().matches(".*Logger.*") and
      loggerMethod.getMethod().hasName("info") and
      snk.asExpr() = loggerMethod.getAnArgument() // Select arguments
    )
    or
    // Detect file input stream sinks
    exists(MethodAccess fileIO |
      fileIO.getMethod().getDeclaringType().getName() = "java.io.FileInputStream" and
      fileIO.getMethod().hasName("FileInputStream") and
      snk.asExpr() = fileIO.getAnArgument() // Select arguments
    )
  }
}

module Flow = DataFlow::Global<MyFlowConfiguration>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, ""
