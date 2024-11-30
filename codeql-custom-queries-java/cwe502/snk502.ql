/**
 * @name 502-snk
 * @kind problem
 * @problem.severity warning
 * @id java/example/sink-detection
 */

 import java
 import semmle.code.java.dataflow.DataFlow
 
 // Detect taint sinks that match the ObjectInputStream constructor
 predicate isSink(DataFlow::Node snk) {
   exists(ConstructorCall c |
     c.getConstructor().getDeclaringType().hasQualifiedName("java.io", "ObjectInputStream") and
     snk.asExpr() = c.getAnArgument()
   )
 }
 
 // Query to output each detected sink with details
 from DataFlow::Node sink
 where isSink(sink)
 select sink,
   "Sink element in type: " +
   sink.getEnclosingCallable().getDeclaringType().getName() +
   ", method: " + sink.getEnclosingCallable().getName() +
   ", signature: " + sink.getEnclosingCallable().getQualifiedName() +
   "(" + sink.getEnclosingCallable().getSignature() + ")" +
   ", sink data type: " + sink.getType().getName()
 
 