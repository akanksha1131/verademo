/**
 * @name 327-src
 * @kind problem
 * @problem.severity warning
 * @id java/example/source-detection
 */

 import java
 import semmle.code.java.dataflow.DataFlow
 
 class RequestMappingAnnotation extends Annotation {
  RequestMappingAnnotation() {
    this.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestMapping")
  }
}

// Define a class for methods annotated with @RequestMapping
class RequestMappingMethod extends Method {
  RequestMappingMethod() { this.getAnAnnotation() instanceof RequestMappingAnnotation }
}

predicate isSource(DataFlow::Node src, string sourceType, string sourceName, string sourceDataType) {
  exists(RequestMappingMethod method, Parameter p |
    p = method.getParameter(_) and
    p.getName() in ["password"] and
    src.asParameter() = p and
    sourceType = "Parameter" and
    sourceName = p.getName() and
    sourceDataType = p.getType().toString()
  )
}
 
 // Query to output each detected source with detailed information
 from DataFlow::Node source, string sourceType, string sourceName, string sourceDataType
 where isSource(source, sourceType, sourceName, sourceDataType)
 select 
   source, 
   "Source's Package: " + 
   source.getEnclosingCallable().getDeclaringType().getPackage().getName() + 
   ", class: " + source.getEnclosingCallable().getDeclaringType().getName() +
   ", function: " + source.getEnclosingCallable().getName() +
   ", signature: " + source.getEnclosingCallable().getQualifiedName() + 
   "(" + source.getEnclosingCallable().getSignature() + ")" +
   ". Source type: " + sourceType +
   ", Source name: " + sourceName +
   ", Source data type: " + sourceDataType
 