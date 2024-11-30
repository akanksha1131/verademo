/**
 * @kind path-problem
 * @name 470path
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
      p.getName() = "command" and
      src.asParameter() = p
    )
  }

  predicate isSink(DataFlow::Node snk) {
    exists(MethodAccess m |
      m.getMethod().hasName("forName") and
      snk.asExpr() = m.getAnArgument()
    )
  }
}

module Flow = TaintTracking::Global<MyFlowConfiguration>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, ""
