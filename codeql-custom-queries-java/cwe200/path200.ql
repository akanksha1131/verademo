/**
 * @kind path-problem
 * @name 200path
 * @id java/example/path-detection
 */

import semmle.code.java.dataflow.TaintTracking

module MyFlowConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { exists(Parameter p | p.getName() in ["username"]) }

  predicate isSink(DataFlow::Node snk) {
    exists(MethodAccess m |
      m.getMethod().hasName("displayErrorForWeb") and
      snk.asExpr() = m.getArgument(0)
    )
  }
}

module Flow = TaintTracking::Global<MyFlowConfiguration>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, ""
