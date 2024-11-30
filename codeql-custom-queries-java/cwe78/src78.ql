/**
 * Enhanced query to detect sources of user-controlled input
 * @name 78-src
 * @kind problem
 * @problem.severity warning
 * @id java/example/source-detection
 */

 import java
 import semmle.code.java.dataflow.DataFlow
 
 // Define sources of user-controlled input, tailored to specific taint sources
 predicate isSource(DataFlow::Node src, string sourceType, string sourceName, string sourceDataType) {
   // Parameters commonly associated with CWEs
   exists(Parameter p |
     p.getName() in [
       "fortuneFile", "host"
     ] and
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
 