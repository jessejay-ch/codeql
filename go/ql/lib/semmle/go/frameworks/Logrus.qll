/** Provides models of commonly used functions in the `github.com/sirupsen/logrus` package. */

import go

/** Provides models of commonly used functions in the `github.com/sirupsen/logrus` package. */
module Logrus {
  /** Gets the package name `github.com/sirupsen/logrus`. */
  string packagePath() {
    result = package(["github.com/sirupsen/logrus", "github.com/Sirupsen/logrus"], "")
  }

  bindingset[result]
  private string getALogResultName() {
    result
        .matches([
            "Debug%", "Error%", "Fatal%", "Info%", "Log%", "Panic%", "Print%", "Trace%", "Warn%"
          ])
  }

  bindingset[result]
  private string getAnEntryUpdatingMethodName() {
    result.regexpMatch("With(Context|Error|Fields?|Time)")
  }

  private class LogFunction extends Function {
    LogFunction() {
      exists(string name | name = getALogResultName() or name = getAnEntryUpdatingMethodName() |
        this.hasQualifiedName(packagePath(), name) or
        this.(Method).hasQualifiedName(packagePath(), ["Entry", "Logger"], name)
      )
    }
  }

  private class LogCall extends LoggerCall::Range, DataFlow::CallNode {
    LogCall() {
      // find calls to logrus logging functions
      this = any(LogFunction f).getACall() and
      // unless there is a sanitizing formatter that is set and no other formatter that
      // does not sanitize inputs is ever set;
      // this is an over-approximation to reduce the number of false positives, but also
      // turns some true positivies into false negatives
      not existsSanitizingFormatter()
    }

    override DataFlow::Node getAMessageComponent() { result = this.getAnArgument() }
  }

  private class StringFormatters extends StringOps::Formatting::Range instanceof LogFunction {
    int argOffset;

    StringFormatters() {
      this.getName().matches("%f") and
      if this.getName() = "Logf" then argOffset = 1 else argOffset = 0
    }

    override int getFormatStringIndex() { result = argOffset }

    override int getFirstFormattedParameterIndex() { result = argOffset + 1 }
  }

  private class SetFormatterFunction extends Function {
    SetFormatterFunction() {
      this.hasQualifiedName(packagePath(), "SetFormatter") or
      this.(Method).hasQualifiedName(packagePath(), "Logger", "SetFormatter")
    }
  }

  private class JSONFormatter extends Type {
    JSONFormatter() { this.hasQualifiedName(packagePath(), "JSONFormatter") }
  }

  private Type sanitizingFormatter() { result instanceof JSONFormatter }

  private predicate usesSanitizingFormatter(DataFlow::CallNode call) {
    // is the argument to the call a sanitizing formatter?
    call.getArgument(0).getType() = sanitizingFormatter().getPointerType()
    or
    // or is there data flow from something of a sanitizing formatter type to the
    // argument of the call?
    exists(DataFlow::Node n |
      // this is a slight approximation since a variable could be set to a
      // sanitizing formatter and then replaced with another one that isn't
      DataFlow::localFlow(n, call.getArgument(0)) and
      n.getType() = sanitizingFormatter().getPointerType()
    )
  }

  private predicate existsSanitizingFormatter() {
    // find uses of `SetFormatter` that have a `JSONFormatter` as argument
    exists(SetFormatterFunction f, DataFlow::CallNode call |
      // find a call to `SetFormatter`
      call = f.getACall() and
      // which receives a sanitizing formatter as argument
      usesSanitizingFormatter(call) and
      // if there is another call to `SetFormatter` with an argument other than `JSONFormatter`,
      // the logger may be using a non-sanitizing output formatter
      not exists(DataFlow::CallNode call2 |
        // find another call to `SetFormatter`
        call2 = f.getACall() and
        // which is not the same as the initial one we found
        call != call2 and
        // which does not receive a sanitizing formatter as argument
        not usesSanitizingFormatter(call2)
      )
    )
  }
}
