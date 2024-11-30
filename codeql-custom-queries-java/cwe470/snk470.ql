/**
 * @name 470-snk
 * @kind problem
 * @problem.severity warnings
 * @id java/example/sink-detection
 */

 import java
 import semmle.code.java.dataflow.DataFlow
 
 predicate isSink(DataFlow::Node snk) {
    exists(MethodAccess m |
        m.getMethod().hasName("forName") and
        snk.asExpr() = m.getAnArgument()
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
 