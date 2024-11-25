
import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.SqlInjectionQuery
import QueryInjectionFlow::PathGraph

// Define dynamic allowed source methods
class SourceMethod extends Method {
  predicate isAllowedSource() {
    this.getSignature() = "com.veracode.verademo.commands.ListenCommand.execute(java.lang.String)" or this.getSignature() = "com.veracode.verademo.commands.RemoveAccountCommand.execute(java.lang.String)" or this.getSignature() = "com.veracode.verademo.controller.BlabController.processBlabbers(java.lang.String,java.lang.String,org.springframework.ui.Model,javax.servlet.http.HttpServletRequest)" or this.getSignature() = "com.veracode.verademo.controller.ToolsController.tools(java.lang.String,java.lang.String,org.springframework.ui.Model)" or this.getSignature() = "com.veracode.verademo.controller.UserController.processProfile(java.lang.String,java.lang.String,java.lang.String,org.springframework.web.multipart.MultipartFile,org.springframework.web.multipart.MultipartHttpServletRequest,javax.servlet.http.HttpServletResponse)" or this.getSignature() = "com.veracode.verademo.controller.UserController.processRegisterFinish(java.lang.String,java.lang.String,java.lang.String,java.lang.String,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse,org.springframework.ui.Model)" or this.getSignature() = "com.veracode.verademo.controller.UserController.processRegister(java.lang.String,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse,org.springframework.ui.Model)" or this.getSignature() = "com.veracode.verademo.model.Blabber.setBlabName(java.lang.String)" or this.getSignature() = "com.veracode.verademo.model.Blabber.setRealName(java.lang.String)" or this.getSignature() = "com.veracode.verademo.model.Blabber.setUsername(java.lang.String)" or this.getSignature() = "com.veracode.verademo.utils.User.setPassword(java.lang.String)" or this.getSignature() = "com.veracode.verademo.controller.UserController.showPasswordHint(java.lang.String)" or this.getSignature() = "com.veracode.verademo.controller.UserController.processLogin(java.lang.String,java.lang.String,java.lang.String,java.lang.String,org.springframework.ui.Model,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)" or this.getSignature() = "com.veracode.verademo.controller.UserController.showLogin(java.lang.String,java.lang.String,org.springframework.ui.Model,javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)" or this.getSignature() = "com.veracode.verademo.controller.ToolsController.fortune(java.lang.String)" or this.getSignature() = "com.veracode.verademo.controller.ToolsController.ping(java.lang.String)" or this.getSignature() = "com.veracode.verademo.controller.UserController.getProfileImageNameFromUsername(java.lang.String)" or this.getSignature() = "com.veracode.verademo.controller.UserController.usernameExists(java.lang.String)" or this.getSignature() = "com.veracode.verademo.controller.UserController.emailUser(java.lang.String)"
  }
}

// Define dynamic allowed sink methods
class SinkMethod extends Method {
  predicate isAllowedSink() {
    this.getSignature() = "com.veracode.verademo.utils.Constants.getJdbcConnectionString()"
  }
}

// Define the query flow from user-controlled sources to sinks
from QueryInjectionSink query, QueryInjectionFlow::PathNode source, QueryInjectionFlow::PathNode sink
where
  queryIsTaintedBy(query, source, sink) and
  source.getMethod().isAllowedSource() and
  query.getMethod().isAllowedSink()
select query, source, sink, 
  "This query depends on a user-provided value", 
  source.getNode(), 
  "user-provided value"
