/**
 * ...
 *
 * @kind path-problem
 * @name Path-test-par
 * @id java/example/path-detection
 * ...
 */

 import semmle.code.java.dataflow.DataFlow

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
 module MyFlowConfiguration implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node src) {
        exists(RequestMappingMethod method, Parameter param |
            param = method.getParameter(_) and
            src.asParameter() = param
        )
    }
 
   /**
    * Define sinks where unvalidated data could lead to vulnerabilities.
    */
   predicate isSink(DataFlow::Node snk) {
     // Detect file access sinks
     exists(MethodAccess fileAccess |
       fileAccess.getMethod().getDeclaringType().getName() = "java.io.File" and
       fileAccess.getMethod().hasName("transferTo") and
       snk.asExpr() = fileAccess.getAnArgument() // Select arguments
     )
     or
     // Detect SQL injection sinks
     exists(MethodAccess sqlMethod |
       sqlMethod.getMethod().getDeclaringType().getName() = "java.sql.Statement" and
       (
         sqlMethod.getMethod().hasName("executeQuery") or
         sqlMethod.getMethod().hasName("executeUpdate") or
         sqlMethod.getMethod().hasName("execute")
       ) and
       snk.asExpr() = sqlMethod.getAnArgument() // Select arguments
     )
     or
     // Detect Runtime.getRuntime().exec()
     exists(MethodAccess runtimeExec |
       runtimeExec.getMethod().getDeclaringType().getName() = "java.lang.Runtime" and
       runtimeExec.getMethod().hasName("exec") and
       snk.asExpr() = runtimeExec.getAnArgument()
     )
     or
     // Detect Runtime.getRuntime().exec(new String[] { ... })
     exists(MethodAccess runtimeArrayExec |
       runtimeArrayExec.getMethod().getDeclaringType().getName() = "java.lang.Runtime" and
       runtimeArrayExec.getMethod().hasName("exec") and
       exists(ArrayCreationExpr arrayExpr |
         runtimeArrayExec.getAnArgument() = arrayExpr and
         arrayExpr.toString().matches(".*bash.*ping.*")
       )
     )
     or
     // Detect object stream access sinks
     exists(MethodAccess objectStreamAccess |
       objectStreamAccess.getMethod().getDeclaringType().getName() = "java.io.ObjectInputStream" and
       objectStreamAccess.getMethod().hasName("readObject") and
       snk.asExpr() = objectStreamAccess.getAnArgument() // Select arguments
     )
     or
     // Detect javax.mail.Message.setSubject()
     exists(MethodAccess emailSubject |
       emailSubject.getMethod().getDeclaringType().getName() = "javax.mail.Message" and
       emailSubject.getMethod().hasName("setSubject") and
       snk.asExpr() = emailSubject.getAnArgument()
     )
     or
     // Detect format method sinks
     exists(MethodAccess formatAccess |
       formatAccess.getMethod().hasName("format") and
       snk.asExpr() = formatAccess.getAnArgument() // Select arguments
     )
     or
     // Detect session management sinks
     exists(MethodAccess sessionUtils |
       sessionUtils.getMethod().getDeclaringType().getName() = "Utils" and
       (
         sessionUtils.getMethod().hasName("setSessionUserName") or
         sessionUtils.getMethod().hasName("setUsernameCookie")
       ) and
       snk.asExpr() = sessionUtils.getArgument(1) // Select arguments
     )
     or
     // Detect Logger method sinks
     exists(MethodAccess loggerMethod |
       loggerMethod.getMethod().getDeclaringType().getName().matches(".*Logger.*") and
       loggerMethod.getMethod().hasName("info") and
       snk.asExpr() = loggerMethod.getAnArgument() // Select arguments
     )
     or
     // Detect InputStream inputStream = new FileInputStream(downloadFile)
     exists(MethodAccess fileInputStream |
       fileInputStream.getMethod().getDeclaringType().getName() = "java.io.FileInputStream" and
       fileInputStream.getMethod().hasName("FileInputStream") and
       snk.asExpr() = fileInputStream.getAnArgument()
     )
     or
     // Detect file.transferTo(new File(path))
     exists(MethodAccess fileTransfer |
       fileTransfer.getMethod().getDeclaringType().getName() = "java.io.File" and
       fileTransfer.getMethod().hasName("transferTo") and
       snk.asExpr() = fileTransfer.getAnArgument()
     )
   }
 }
 
 module Flow = DataFlow::Global<MyFlowConfiguration>;
 
 import Flow::PathGraph
 
 from Flow::PathNode source, Flow::PathNode sink
 where Flow::flowPath(source, sink)
 select sink.getNode(), source, sink, ""
 