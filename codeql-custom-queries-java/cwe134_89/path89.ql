/**
 * @kind path-problem
 * @name 89_134_path
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
      p.getName() in ["username", "password", "cpassword"] and
      src.asParameter() = p
    )
  }

  predicate isSink(DataFlow::Node snk) {
    exists(MethodAccess sqlMethod |
      (
        sqlMethod.getMethod().hasName("executeQuery") or
        sqlMethod.getMethod().hasName("executeUpdate") or
        sqlMethod.getMethod().hasName("execute")
      ) and
      snk.asExpr() = sqlMethod.getAnArgument()
    )
  }
}

module Flow = TaintTracking::Global<MyFlowConfiguration>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, ""
