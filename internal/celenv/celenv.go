// Package celenv defines the structured.cel evaluation environment shared by
// rule evaluation and pack instantiation.
package celenv

import (
	"cel.dev/cel-go/cel"
	celast "cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/ext"
)

// PackVariable names the variable that exposes a pack's checked parameters.
const PackVariable = "pack"

// Extension library versions are pinned so a dependency update cannot
// silently add functions or change their cost model. Each pinned version
// includes runtime cost tracking for its allocating functions, so the
// rule's costLimit bounds them like built-in operations.
const (
	// ListsVersion 4 provides slice, flatten, distinct, range, reverse,
	// sort, sortBy, first, and last, with element-proportional flatten cost.
	ListsVersion = 4
	// StringsVersion 5 provides charAt, indexOf, lastIndexOf, lowerAscii,
	// upperAscii, replace, split, substring, trim, join, reverse, format,
	// and strings.quote, with cost tracking and bounded format precision.
	StringsVersion = 5
	// maximumRangeSize bounds lists.range allocation independently of cost.
	maximumRangeSize = 100_000
)

// New returns the statically typed structured.cel environment. It contains
// only deterministic, offline extensions: no network, regex-extraction,
// set, math, or clock functions beyond the provided now variable.
func New() (*cel.Env, error) {
	return cel.NewEnv(
		ext.Lists(ext.ListsVersion(ListsVersion), ext.ListsMaxRangeSize(maximumRangeSize)),
		ext.Strings(ext.StringsVersion(StringsVersion), ext.StringsValidateFormatCalls(true)),
		ext.TwoVarComprehensions(ext.TwoVarComprehensionsVersion(0)),
		cel.Variable("repo", cel.DynType), cel.Variable("git", cel.DynType),
		cel.Variable("files", cel.ListType(cel.DynType)), cel.Variable("documents", cel.ListType(cel.DynType)),
		cel.Variable("items", cel.ListType(cel.DynType)), cel.Variable("params", cel.DynType),
		cel.Variable("now", cel.TimestampType),
		cel.Variable(PackVariable, cel.MapType(cel.StringType, cel.DynType)),
	)
}

// PackReads describes how a type-checked expression reads the pack variable.
type PackReads struct {
	// Any is true when the expression reads pack at all.
	Any bool
	// Names lists parameter names read through pack.name, has(pack.name),
	// or pack['name'] with a constant string key.
	Names map[string]bool
	// Dynamic is true when pack is read in another way, such as pack[key],
	// 'name' in pack, or passing the whole map, so the parameters read
	// cannot be determined statically.
	Dynamic bool
}

// ReferencesPack reports whether the type-checked expression reads the pack
// variable. It inspects the checker's reference map and the navigable AST,
// so string literals, field names such as params.pack, and comprehension
// variables that happen to be named pack do not count. An expression that
// does not compile returns an error; rule validation reports it.
func ReferencesPack(environment *cel.Env, expression string) (bool, error) {
	reads, err := ReadsOfPack(environment, expression)
	return reads.Any, err
}

// ReadsOfPack type-checks the expression and reports which pack parameters
// it reads, using the same identifier resolution as ReferencesPack.
func ReadsOfPack(environment *cel.Env, expression string) (PackReads, error) {
	reads := PackReads{Names: map[string]bool{}}
	checked, issues := environment.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return reads, issues.Err()
	}
	native := checked.NativeRep()
	references := native.ReferenceMap()
	identifiers := celast.MatchDescendants(celast.NavigateAST(native), func(expr celast.NavigableExpr) bool {
		if expr.Kind() != celast.IdentKind || expr.AsIdent() != PackVariable {
			return false
		}
		reference, resolved := references[expr.ID()]
		return resolved && reference.Name == PackVariable && !boundByComprehension(expr)
	})
	for _, identifier := range identifiers {
		reads.Any = true
		if name, ok := constantParameterRead(identifier); ok {
			reads.Names[name] = true
		} else {
			reads.Dynamic = true
		}
	}
	return reads, nil
}

// constantParameterRead returns the parameter name when the pack identifier
// is the operand of a field selection or an index with a constant string.
func constantParameterRead(identifier celast.NavigableExpr) (string, bool) {
	parent, ok := identifier.Parent()
	if !ok {
		return "", false
	}
	switch parent.Kind() {
	case celast.SelectKind:
		return parent.AsSelect().FieldName(), true
	case celast.CallKind:
		call := parent.AsCall()
		args := call.Args()
		if (call.FunctionName() != operators.Index) || len(args) != 2 || args[0].ID() != identifier.ID() {
			return "", false
		}
		if args[1].Kind() != celast.LiteralKind {
			return "", false
		}
		if name, ok := args[1].AsLiteral().(types.String); ok {
			return string(name), true
		}
	}
	return "", false
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
