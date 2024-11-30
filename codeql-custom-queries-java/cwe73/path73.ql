/**
 * @kind path-problem
 * @name 73path
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
    exists(Parameter p |
      p.getName() in ["imageName", "username"] and
      src.asParameter() = p
    )
  }

  predicate isSink(DataFlow::Node snk) {
    exists(ConstructorCall c |
      c.getConstructor().getDeclaringType().hasQualifiedName("java.io", "FileInputStream") and
      snk.asExpr() = c.getAnArgument()
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.web.multipart", "MultipartFile") and
      ma.getMethod().getName() = "transferTo" and
      snk.asExpr() = ma.getAnArgument()
    )
  }
}

module Flow = TaintTracking::Global<MyFlowConfiguration>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, ""
