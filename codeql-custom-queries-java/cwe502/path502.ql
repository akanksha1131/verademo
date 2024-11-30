/**
 * @kind path-problem
 * @name 502path
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
      p.getName() in ["req"] and
      src.asParameter() = p
    )
  }

  predicate isSink(DataFlow::Node snk) {
    exists(ConstructorCall c |
      c.getConstructor().getDeclaringType().hasQualifiedName("java.io", "ObjectInputStream") and
      snk.asExpr() = c.getAnArgument()
    )
    // exists(MethodAccess m |
    //     m.getMethod().getDeclaringType().getName() = "UserFactory" and
    //     (
    //       m.getMethod().hasName("createFromRequest")
    //     ) and
    //     snk.asExpr() = m.getAnArgument()
    //   )
  }
}

module Flow = TaintTracking::Global<MyFlowConfiguration>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, ""
