/**
 * @name snk117
 * @kind problem
 * @problem.severity warning
 * @id java/example/sink-detection
 */

 import java
 import semmle.code.java.dataflow.DataFlow
 
 /**
  * Predicate to identify sinks as `AddExpr` instances where the left operand is 
  * a `StringLiteral` with the value "redirect:".
  */
 predicate isSink(DataFlow::Node sink) {
   exists(AddExpr addExpr, StringLiteral literal |
     sink.asExpr() = addExpr and
     addExpr.getLeftOperand() = literal and
     literal.getValue() = "redirect:"
   )
 }
 
 // Query to output each detected sink with detailed information
 from DataFlow::Node sink
 where isSink(sink)
 select sink,
   "Sink detected in type: " + sink.getEnclosingCallable().getDeclaringType().getName() +
   ", method: " + sink.getEnclosingCallable().getName() +
   ", signature: " + sink.getEnclosingCallable().getQualifiedName() + "(" +
   sink.getEnclosingCallable().getSignature() + ")" +
   ", data type: " + sink.getType().getName()
 