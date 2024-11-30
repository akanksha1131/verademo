/**
 * @kind path-problem
 * @name 78path
 * @id java/example/path-detection
 */

import semmle.code.java.dataflow.TaintTracking

module MyFlowConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    exists(Parameter p |
      p.getName() in ["fortuneFile", "host"] and
      src.asParameter() = p
    )
  }

  predicate isSink(DataFlow::Node snk) {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
      ma.getMethod().getName() = "exec" and
      snk.asExpr() = ma.getAnArgument()
    )
  }
}

module Flow = TaintTracking::Global<MyFlowConfiguration>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, ""
