/**
 * @name 78-snk
 * @kind problem
 * @problem.severity warnings
 * @id java/example/sink-detection
 */

 import java
 import semmle.code.java.dataflow.DataFlow
 
 predicate isSink(DataFlow::Node snk) {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
      ma.getMethod().getName() = "exec" and
      snk.asExpr() = ma.getAnArgument()
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
 