/**
 * @kind path-problem
 * @name 117path
 * @id java/example/path-detection
 */

 import semmle.code.java.dataflow.TaintTracking

module MyFlowConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    exists(Parameter p |
        p.getName() = "target" and
        src.asParameter() = p
      )
  }


  predicate isSink(DataFlow::Node sink) {
    exists(AddExpr addExpr, StringLiteral literal |
      sink.asExpr() = addExpr and
      addExpr.getLeftOperand() = literal and
      literal.getValue() = "redirect:"
    )
  }
}

module Flow = TaintTracking::Global<MyFlowConfiguration>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, ""
