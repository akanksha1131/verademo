/**
 * @name srv
 * @kind problem
 * @problem.severity warning
 * @id java/example/request-mapping-param-tracker
 */

 import java
 import semmle.code.java.dataflow.DataFlow
 
 // Define a class for @RequestMapping annotations
 class RequestMappingAnnotation extends Annotation {
     RequestMappingAnnotation() {
         this.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestMapping")
     }
 }
 
 // Define a class for methods annotated with @RequestMapping
 class RequestMappingMethod extends Method {
     RequestMappingMethod() {
         this.getAnAnnotation() instanceof RequestMappingAnnotation
     }
 }
 
 // Define sources of user-controlled input: parameters of methods annotated with @RequestMapping
 predicate isSource(DataFlow::Node src) {
     exists(RequestMappingMethod method, Parameter param |
         param = method.getParameter(_) and
         src.asParameter() = param
     )
 }
 
 // Query to output detected sources
 from DataFlow::Node source
 where isSource(source)
 select 
     source, 
     "Parameter '" + source.asParameter().getName() + 
     "' of type '" + source.asParameter().getType().toString() + 
     "' in method '" + source.getEnclosingCallable().getName() +
     "' is a potential source (tracked from @RequestMapping)."
 