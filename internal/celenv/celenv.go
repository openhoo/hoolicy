// Package celenv defines the structured.cel evaluation environment shared by
// rule evaluation and pack instantiation.
package celenv

import (
	"cel.dev/cel-go/cel"
	celast "cel.dev/cel-go/common/ast"
)

// PackVariable names the variable that exposes a pack's checked parameters.
const PackVariable = "pack"

// New returns the statically typed structured.cel environment.
func New() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("repo", cel.DynType), cel.Variable("git", cel.DynType),
		cel.Variable("files", cel.ListType(cel.DynType)), cel.Variable("documents", cel.ListType(cel.DynType)),
		cel.Variable("items", cel.ListType(cel.DynType)), cel.Variable("params", cel.DynType),
		cel.Variable("now", cel.TimestampType),
		cel.Variable(PackVariable, cel.MapType(cel.StringType, cel.DynType)),
	)
}

// ReferencesPack reports whether the type-checked expression reads the pack
// variable. It inspects the checker's reference map and the navigable AST,
// so string literals, field names such as params.pack, and comprehension
// variables that happen to be named pack do not count. An expression that
// does not compile returns an error; rule validation reports it.
func ReferencesPack(environment *cel.Env, expression string) (bool, error) {
	checked, issues := environment.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return false, issues.Err()
	}
	native := checked.NativeRep()
	references := native.ReferenceMap()
	matches := celast.MatchDescendants(celast.NavigateAST(native), func(expr celast.NavigableExpr) bool {
		if expr.Kind() != celast.IdentKind || expr.AsIdent() != PackVariable {
			return false
		}
		reference, resolved := references[expr.ID()]
		return resolved && reference.Name == PackVariable && !boundByComprehension(expr)
	})
	return len(matches) > 0, nil
}

// boundByComprehension reports whether an enclosing comprehension binds the
// identifier's name in the subexpression that contains it. Iteration
// variables are in scope in the loop condition and step; the accumulator
// additionally in the result. The range and initializer are outside scope.
func boundByComprehension(identifier celast.NavigableExpr) bool {
	name := identifier.AsIdent()
	child := identifier
	for parent, ok := child.Parent(); ok; parent, ok = child.Parent() {
		if parent.Kind() == celast.ComprehensionKind {
			comprehension := parent.AsComprehension()
			inLoop := child.ID() == comprehension.LoopCondition().ID() || child.ID() == comprehension.LoopStep().ID()
			inResult := child.ID() == comprehension.Result().ID()
			iterBound := comprehension.IterVar() == name || (comprehension.HasIterVar2() && comprehension.IterVar2() == name)
			if (inLoop && iterBound) || ((inLoop || inResult) && comprehension.AccuVar() == name) {
				return true
			}
		}
		child = parent
	}
	return false
}
