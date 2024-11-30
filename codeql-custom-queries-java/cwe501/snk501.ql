/**
 * @name 501-snk
 * @kind problem
 * @problem.severity warnings
 * @id java/example/sink-detection
 */

 import java
 import semmle.code.java.dataflow.DataFlow
 
 predicate isSink(DataFlow::Node snk) {
   // Detect session management sinks
   exists(MethodAccess sessionUtils |
     sessionUtils.getMethod().getDeclaringType().getName() = "Utils" and
     (
       sessionUtils.getMethod().hasName("setSessionUserName")
     ) and
     snk.asExpr() = sessionUtils.getArgument(2)
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
 