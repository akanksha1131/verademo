/**
 * @name 73-snk
 * @kind problem
 * @problem.severity warnings
 * @id java/example/sink-detection
 */

import java
import semmle.code.java.dataflow.DataFlow

predicate isSink(DataFlow::Node snk) {
  exists(ConstructorCall c |
    c.getConstructor().getDeclaringType().hasQualifiedName("java.io", "FileInputStream") and
    snk.asExpr() = c.getAnArgument()
  )
  or
  // exists(MethodAccess m |
  //   // Match `File.transferTo` method
  //   m.getMethod().getDeclaringType().hasQualifiedName("java.io", "File") and
  //   m.getMethod().getName() = "transferTo" and
  //   snk.asExpr() = m.getAnArgument()
  // )
  exists(MethodAccess ma |
    ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.web.multipart", "MultipartFile") and
    ma.getMethod().getName() = "transferTo" and
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
