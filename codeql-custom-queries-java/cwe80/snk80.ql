/**
 * @name 80-snk
 * @kind problem
 * @problem.severity warnings
 * @id java/example/sink-detection
 */

import java
import semmle.code.java.dataflow.DataFlow

predicate isSink(DataFlow::Node sink) {
  exists(MethodAccess call |
    call.getMethod().hasQualifiedName("java.sql", "PreparedStatement", "setString") and
    sink.asExpr() = call.getArgument(1)
  )
}

from DataFlow::Node sink
where
  isSink(sink) and
  exists(ClassOrInterface c |
    c.getName().matches("BlabController") and
    sink.getEnclosingCallable().getDeclaringType() = c
  )
select sink,
  "Sink element in type: " + sink.getEnclosingCallable().getDeclaringType().getName() + ", method: "
    + sink.getEnclosingCallable().getName() + ", signature: " +
    sink.getEnclosingCallable().getQualifiedName() + "(" +
    sink.getEnclosingCallable().getSignature() + ")" + ", sink data type: " +
    sink.getType().getName()
