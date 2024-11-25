/**
 * @name Query built from user-controlled sources
 * @description Building a SQL or Java Persistence query from user-controlled sources
 * is vulnerable to insertion of malicious code by the user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id java/sql-injection
 * @tags security
 * external/cwe/cwe-089
 * external/cwe/cwe-564
 */

 import java
 import semmle.code.java.dataflow.FlowSources
 import semmle.code.java.security.SqlInjectionQuery
 import QueryInjectionFlow::PathGraph
 
 // Define the query flow from user-controlled sources to sinks
 from QueryInjectionSink query, QueryInjectionFlow::PathNode source, QueryInjectionFlow::PathNode sink
 where queryIsTaintedBy(query, source, sink)
 select query, source, sink, 
   "This query depends on a user-provided value", 
   source.getNode(), 
   "user-provided value"
 