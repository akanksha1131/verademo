/**
 * @kind path-problem
 * @name 327path
 * @id java/example/path-detection
 */

import semmle.code.java.dataflow.TaintTracking

class RequestMappingAnnotation extends Annotation {
  RequestMappingAnnotation() {
    this.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestMapping")
  }
}

// Define a class for methods annotated with @RequestMapping
class RequestMappingMethod extends Method {
  RequestMappingMethod() { this.getAnAnnotation() instanceof RequestMappingAnnotation }
}

module MyFlowConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    exists(RequestMappingMethod method, Parameter p |
      p = method.getParameter(_) and
      p.getName() in ["password"] and
      src.asParameter() = p 
    )
  }

  predicate isSink(DataFlow::Node snk) {
    exists(MethodAccess m |
      m.getMethod().hasName("md5") and
      snk.asExpr() = m.getArgument(0)
    )
  }
//   predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
//     exists(ClassOrInterface c | 
//         c.getName().matches("UserController") and 
//         (node1.getEnclosingCallable().getDeclaringType() = c or
//          node2.getEnclosingCallable().getDeclaringType() = c)
//       )
//   }
}

module Flow = TaintTracking::Global<MyFlowConfiguration>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where 
  Flow::flowPath(source, sink) and
  exists(ClassOrInterface c | 
    c.getName().matches("UserController") and 
    (source.getNode().getEnclosingCallable().getDeclaringType() = c and
     sink.getNode().getEnclosingCallable().getDeclaringType() = c)
  )
select sink.getNode(), source, sink, ""