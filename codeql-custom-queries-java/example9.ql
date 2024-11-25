import semmle.code.java.dataflow.TaintTracking

module MyFlowConfiguration implements DataFlow::ConfigSig {
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

  predicate isSink(DataFlow::Node sink) {
    ...
  }
}

module MyFlow = TaintTracking::Global<MyFlowConfiguration>;